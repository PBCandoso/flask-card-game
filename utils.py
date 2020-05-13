import asyncio
import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

import PyKCS11
import wget
import requests
from cryptography.x509 import ocsp
from cryptography.hazmat.primitives.hashes import SHA1
from cryptography import x509
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import utils, rsa, padding
from cryptography.x509.oid import NameOID

from jwcrypto import jwe, jwk, jwt, jws
from jwcrypto.common import json_encode
from OpenSSL.crypto import load_privatekey, dump_privatekey, FILETYPE_PEM

SECRET_JWE = "descobre"
SECRET_KEY_JWT_CMD = "3VVvsUSG1fQAgSEmmUCE7W-OqBHMQwdNOf4xWq32h0_b_fKitMbQgRjr_XejHGceJfrUCK86zSNDp5OMFbaS0I0KtTmfnnjGX6AM4oZ-S38s4Sf-r9W7A84wzgfzOrTWT77i_r9N2vL7jTN7aCrCxpCdbDuidbqH6qQsZT-uZe86JbIfUKOaOooPZ1h29nzcycx64A7r6UI7O90DYGLqiw1exmfISQZij7UR8fUdi-fvt6QUjH0qIMIN9re4kjnqmB1Hgw6yyymqLTLptWtOx6Xr6iPbNWcDVlInGzBCEBjiUDmt8-MXLrB6s8JbRAQndKyOTbhX9tbr-CaanV-iNw"
# Secret symmetric key to sign the JWS
JWK_KEY = {"k":"Wal4ZHCBsml0Al_Y8faoNTKsXCkw8eefKXYFuwTBOpA","kty":"oct"}


logger = logging.getLogger('root')

class Crypto():

	def __init__(self, symmetric_cipher="", cipher_mode="", digest_function=""):
		self.cipher = symmetric_cipher
		self.mode = cipher_mode
		self.digest = digest_function
		self.symmetric_key = None
		self.public_key = None
		self.private_key = None
		self.shared_key = None
		self.mac = None
		self.iv = None
		self.tag = None 			# GCM tag
		self.nonce = None 			# ChaCha20 nonce

		self.roots = dict()
		self.intermediate_certs = dict()
		self.user_cert = dict()
		self.chain = list()
		self.server_cert = None
		self.rsa_public_key = None
		self.rsa_private_key = None
		self.signature = None
		self.server_public_key = None
		self.auth_nonce = None
		self.server_ca_cert = None
		self.client_cert = None


	# decodes cmd encryption
	def decode_cmd_token(self, cmd_token):
		jwetoken = jwe.JWE()

		with open('./server_key/server_key.pem', 'rb') as f:
			private_key_buffer = f.read()

		priv_key = load_privatekey(FILETYPE_PEM, private_key_buffer, SECRET_JWE.encode())
		priv_key_str = dump_privatekey(FILETYPE_PEM, priv_key)
		priv_key_jwk = jwk.JWK.from_pem(priv_key_str)

		jwetoken.deserialize(cmd_token, key=priv_key_jwk)
		payload = jwetoken.payload

		return payload

	def generate_token(self, payload):
		key = jwk.JWK(**JWK_KEY)
		token = jwt.JWT(header={"alg": "HS256"},claims=payload)
		signed = token.make_signed_token(key)
		return token.serialize()

	def validate_token(self,token):
		key = jwk.JWK(**JWK_KEY)
		jwstoken = jws.JWS()
		jwstoken.deserialize(token)
		try:
			jwstoken.verify(key)
			return True
		except:
			return False

	def get_payload(self,token):
		key = jwk.JWK(**JWK_KEY)
		jwstoken = jws.JWS()
		jwstoken.deserialize(token)
		jwstoken.verify(key)
		return jwstoken.payload


	# Generates shared key (server)
	def dh_server(self, p, g, bytes_public_key):
		pn = dh.DHParameterNumbers(p, g)
		parameters = pn.parameters(default_backend())
		self.private_key = parameters.generate_private_key()
		
		peer_public_key = self.private_key.public_key()
		self.public_key = peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)
		
		public_key_client = crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
		self.shared_key = self.private_key.exchange(public_key_client)
		
		return True


	# Create shared key between client and server
	def create_shared_key(self, bytes_public_key):
		public_key_server = crypto_serialization.load_pem_public_key(bytes_public_key,backend=default_backend())
		self.shared_key = self.private_key.exchange(public_key_server)


	# Generate shared key (client)
	def dh_client(self):
		parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())

		self.private_key = parameters.generate_private_key()
		a_peer_public_key = self.private_key.public_key()
		p = parameters.parameter_numbers().p
		g = parameters.parameter_numbers().g
		y = a_peer_public_key.public_numbers().y

		self.public_key = a_peer_public_key.public_bytes(crypto_serialization.Encoding.PEM,crypto_serialization.PublicFormat.SubjectPublicKeyInfo)

		return(self.public_key, p, g, y)

	# Generates MAC with a digest function
	def mac_gen (self, my_text):

		if(self.digest == "SHA256"):
			a = hashes.SHA256()
		elif(self.digest == "SHA384"):
			a = hashes.SHA384()
		elif(self.digest == "SHA512"):
			a = hashes.SHA512()

		h = hmac.HMAC(self.symmetric_key, a, backend=default_backend())
		h.update(my_text)

		self.mac = binascii.hexlify(h.finalize()) 



	# Symmetric key derived from shared key
	def symmetric_key_gen(self):

		if(self.digest == "SHA256"):
			a = hashes.SHA256()
		elif(self.digest == "SHA384"):
			a = hashes.SHA384()
		elif(self.digest == "SHA512"):
			a = hashes.SHA512()
		else:
			raise Exception("Digest function unsupported")

		kdf = HKDF(
			algorithm=a,
			length=32,
			salt=None,
			info=b'handshake data',
			backend=default_backend()
		)

		key = kdf.derive(self.shared_key)

		if self.cipher == 'AES':
			self.symmetric_key = key[:16]
		elif self.cipher == '3DES':
 			self.symmetric_key = key[:8]
		elif self.cipher == 'CHACHA20':
			self.symmetric_key = key[:32]


	# Encryption with given ciphers and modes
	def encrypt(self, data):
		
		backend = default_backend()
		cipher = None
		block_size = 0
		mode = None
		value = os.urandom(16)

		if self.cipher != 'CHACHA20':
			self.iv = value
			if self.mode == 'CBC':
				if self.cipher == '3DES': self.iv = self.iv[:8]
				mode = modes.CBC(self.iv)
			elif self.mode == 'GCM':
				mode = modes.GCM(self.iv)
			else:
				raise Exception("Cipher mode unsupported")

		if self.cipher == 'AES':
			block_size = algorithms.AES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)		
		elif self.cipher == '3DES':
			block_size = algorithms.TripleDES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
		elif self.cipher == 'CHACHA20':
			self.nonce = value
			a = algorithms.ChaCha20(self.symmetric_key, self.nonce)
			cipher = Cipher(a, mode=None, backend=backend)
		else:
			raise Exception("Symmetric cipher unsupported")


		encryptor = cipher.encryptor()

		if (self.mode != 'GCM') and (self.cipher != 'CHACHA20'):
			padding = block_size - len(data) % block_size

			padding = 16 if padding and self.cipher == 'AES' == 0 else padding 
			padding = 8 if padding and self.cipher == '3DES' == 0 else padding 

			data += bytes([padding]*padding)
			ct = encryptor.update(data)

		elif self.cipher == 'CHACHA20':
			ct = encryptor.update(data)
		else:
			ct = encryptor.update(data)+encryptor.finalize()
			self.tag = encryptor.tag

		return ct


	def decrypt(self, data, iv=None, tag=None, nonce=None):
		backend = default_backend()
		cipher = None
		block_size = 0

		if self.cipher != 'CHACHA20':
			if self.mode == 'GCM':
				mode = modes.GCM(iv, tag)
			elif self.mode == 'CBC':
				if iv is not None:
					mode = modes.CBC(iv)
			else:
				raise Exception("Cipher mode not available")

		if self.cipher == 'AES':
			block_size = algorithms.AES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.AES(self.symmetric_key), mode, backend=backend)
		elif self.cipher == '3DES':
			block_size = algorithms.TripleDES(self.symmetric_key).block_size
			cipher = Cipher(algorithms.TripleDES(self.symmetric_key), mode, backend=backend)
		elif algorithm == 'CHACHA20':
			a = algorithms.ChaCha20(self.symmetric_key, nonce)
			cipher = Cipher(a, mode=None, backend=backend)
		else:
			raise Exception("Symmetric cipher not available")
		
		decryptor = cipher.decryptor()
		ct = decryptor.update(data)+decryptor.finalize()
		
		if (self.mode == 'GCM') or (self.cipher=='CHACHA20'):
			return ct
		return ct[:-ct[-1]]


	def get_certificate_bytes(self,cert):
		return cert.public_bytes(crypto_serialization.Encoding.PEM)


	def load_key_from_file(self,filename):
		with open(filename, "rb") as f:
			private_key=crypto_serialization.load_pem_private_key(f.read(),password=None,backend=default_backend())
		return private_key


	def load_private_key(self, stream):
		return crypto_serialization.load_pem_private_key(
			stream,
			backend=default_backend(),
			password=None

		)


	def load_public_key(self, stream):
		return crypto_serialization.load_pem_public_key(
			stream,
			backend=default_backend()
		)


	def validate_cert(self,cert):
		today = datetime.now().timestamp()
		return cert.not_valid_before.timestamp() <= today <= cert.not_valid_after.timestamp()


	def load_cert_bytes(self,cert_bytes):
		return x509.load_pem_x509_certificate(cert_bytes, default_backend())


	def load_cert(self,filename):

		try:
			with open(filename, "rb") as pem_file:
				pem_data = pem_file.read()
				cert = x509.load_pem_x509_certificate(pem_data, default_backend())
			return cert
		except:
			logger.debug("Not PEM.")
		try:
			with open(filename, "rb") as pem_file:
				pem_data = pem_file.read()
				cert = x509.load_der_x509_certificate(pem_data, default_backend())
			return cert
		except:
			logger.debug("Not DER.")


	# Builds certificate chain  
	def build_issuers(self,chain, cert):
		chain.append(cert)

		issuer = cert.issuer.rfc4514_string()
		subject = cert.subject.rfc4514_string()


		if issuer == subject and subject in self.roots:
			return 

		if issuer in self.intermediate_certs:
			return self.build_issuers(chain, self.intermediate_certs[issuer])

		if issuer in self.roots:
			return self.build_issuers(chain, self.roots[issuer])

		return


	def validate_server_chain(self,base_cert, root_cert):

		self.roots[root_cert.subject.rfc4514_string()] = root_cert

		self.build_issuers(self.chain,base_cert)

		for i,cert in enumerate(self.chain):
			flag=self.validate_cert(cert)
			flag3=self.validate_server_purpose(cert,i)

			if not flag or not flag3:
				return False

		for i in range(0,len(self.chain)):
			if i==len(self.chain)-1:
				break

			#Validate cert signature
			flag1=self.validate_cert_signature(self.chain[i],self.chain[i+1])

			#Validate common name with issuer
			flag2=self.validate_cert_common_name(self.chain[i],self.chain[i+1])

			#Validate crl
			flag4=self.validate_revocation(self.chain[i],self.chain[i+1])
			if not flag1 or not flag2 or flag4:
				return False



		return flag and flag1 and flag2


	def key_pair_gen(self, length):
		valid_lengths = [1024, 2048, 4096]

		if length not in valid_lengths:
			logger.debug("ERROR - Not a valid length!")
			return 


		private_key = rsa.generate_private_key(
			public_exponent=65537, 
			key_size=length,
			backend=default_backend()
		)

		pem = private_key.private_bytes(
			encoding=crypto_serialization.Encoding.PEM,
			format=crypto_serialization.PrivateFormat.PKCS8,
			encryption_algorithm=crypto_serialization.NoEncryption()
		)

		priv_key = base64.b64encode(pem).decode()

		public_key = private_key.public_key()
		pem = public_key.public_bytes(
			encoding=crypto_serialization.Encoding.PEM,
			format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo
		)
		pub_key = base64.b64encode(pem).decode()

		return (pub_key, priv_key)


	def load_cert_revocation_list(self,filename,file_type):
		with open(filename, "rb") as pem_file:
			pem_data = pem_file.read()
			if file_type=="der":
				cert = x509.load_der_x509_crl(pem_data, default_backend())
			elif file_type=="pem":
				cert = x509.load_pem_x509_crl(pem_data, default_backend())

		return cert


	def validate_cert_signature(self,cert_to_check,issuer_cert):

		cert_to_check_signature=cert_to_check.signature
		issuer_public_key=issuer_cert.public_key()

		try:
			issuer_public_key.verify(cert_to_check_signature,cert_to_check.tbs_certificate_bytes,padding.PKCS1v15(),cert_to_check.signature_hash_algorithm)
		except:
			logger.debug("Failed to verify signature.")
			return False

		return True


	def validate_server_purpose(self,cert,index):

		if index==0:
			flag=False
			for c in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
				if c.dotted_string=="1.3.6.1.5.5.7.3.1":
					flag=True
					break
			return flag
		else:
			if cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign==True:
				return True
			return False


	#Validates the revocation of a certificate through CRL, DELTA CRL and OCSP
	def validate_revocation(self,cert_to_check,issuer_cert):

		try:
			builder = ocsp.OCSPRequestBuilder()

			builder = builder.add_certificate(cert_to_check, issuer_cert, SHA1())
			req = builder.build()
			for j in cert_to_check.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value:
				if j.access_method.dotted_string == "1.3.6.1.5.5.7.48.1": 
					rev_list=None

					#Downloading list
					der=req.public_bytes(crypto_serialization.Encoding.DER)

					ocsp_link=j.access_location.value
					r=requests.post(ocsp_link, headers={'Content-Type': 'application/ocsp-request'},data=der)


					ocsp_resp = ocsp.load_der_ocsp_response(r.content)
					if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
						return False
					return True

		except Exception as e:
			logger.debug("OCSP not available")


		try:
			for i in cert_to_check.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
				for b in i.full_name:
					rev_list=None
					#Downloading list
					file_name=wget.download(b.value)
					print()
					#read revocation list
					try:
						rev_list=self.load_cert_revocation_list(file_name,"pem")
					except Exception as e :
						logger.debug(e)
					try:
						rev_list=self.load_cert_revocation_list(file_name,"der")
					except:
						logger.debug("Not der.")
					if rev_list is None:
						return False

					flag=cert_to_check.serial_number in [l.serial_number for l in rev_list]
			try:
				for i in cert_to_check.extensions.get_extension_for_class(x509.FreshestCRL).value:
					for b in i.full_name:
						rev_list=None
						#Downloading list
						file_name=wget.download(b.value)
						#read revocation list
						try:
							rev_list=self.load_cert_revocation_list(file_name,"pem")
						except Exception as e :
							logger.debug(e)
						try:
							rev_list=self.load_cert_revocation_list(file_name,"der")
						except:
							logger.debug("Not der.")
						if rev_list is None:
							return False

						flag=cert_to_check.serial_number in [l.serial_number for l in rev_list]
			except:
				logger.debug("DELTA CRL not available.")

			for i in issuer_cert.extensions.get_extension_for_class(x509.CRLDistributionPoints).value:
				for b in i.full_name:
					rev_list=None
					#Downloading list
					file_name=wget.download(b.value)
					print()


					#read revocation list
					try:
						rev_list=self.load_cert_revocation_list(file_name,"pem")
					except Exception as e :
						logger.debug(e)

					try:
						rev_list=self.load_cert_revocation_list(file_name,"der")
					except:
						logger.debug("Not der.")
					if rev_list is None:
						return False

					flag1=issuer_cert.serial_number in [l.serial_number for l in rev_list]

					return flag1 or flag

			try:
				for i in issuer_cert.extensions.get_extension_for_class(x509.FreshestCRL).value:
					for b in i.full_name:
						rev_list=None
						#Downloading list
						file_name=wget.download(b.value)


						#read revocation list
						try:
							rev_list=self.load_cert_revocation_list(file_name,"pem")
						except Exception as e:
							logger.debug(e)

						try:
							rev_list=self.load_cert_revocation_list(file_name,"der")
						except:
							logger.debug("Not der.")
						if rev_list is None:
							return False

						flag1=issuer_cert.serial_number in [l.serial_number for l in rev_list]

			except:
				logger.debug("DELTA CRL not available.")
			return flag1 or flag



		except Exception as e:
			logger.debug("CRL not available")

		return True


	def validate_cert_common_name(self,cert_to_check,issuer_cert):
		if (self.get_issuer_common_name(cert_to_check)!=self.get_common_name(issuer_cert)):
			return False 
		return True


	def get_common_name(self,cert):
		try:
			names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
			return names[0].value
		except x509.ExtensionNotFound:
			return None


	def get_issuer_common_name(self,cert):
		try:
			names = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
			return names[0].value
		except x509.ExtensionNotFound:
			return None


	def rsa_signing(self, message, private_key):

		signature = private_key.sign(
			message,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)

		return signature


	def rsa_signature_verification (self,signature, message, public_key):
		try:
			public_key.verify(
				signature,
				message,
				padding.PSS(
					mgf=padding.MGF1(hashes.SHA256()),
					salt_length=padding.PSS.MAX_LENGTH
				),
				hashes.SHA256()
			)
		except Exception as e:
			logger.debug("Server signature validation failed!")
			return False

		return True