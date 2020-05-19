import json
import base64
import argparse
import coloredlogs, logging
import os
import getpass
from binascii import b2a_base64, a2b_base64, hexlify, unhexlify
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes 
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.fernet import Fernet
from cryptography import exceptions

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

	def __init__(self, mode="player"):
		self.rsa_public_key = None
		self.rsa_private_key = None
		self.all_fernet_keys = []

		if mode == "player":
			self.table_public_key = None
			self.bit_commitment = None
			self.commitment_reveal = None
			self.other_bit_commitments = {}
			self.other_commitments_reveal = {}
			self.fernet_key = None
		elif mode == "table":
			self.players_public_keys = {}
			self.players_bit_commitments = {}
			self.players_commitments_reveal = {}


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
		token.make_signed_token(key)
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

	def key_pair_gen(self, length):
		valid_lengths = [1024, 2048, 4096]

		if length not in valid_lengths:
			logger.error('Not a valid length!')
			return False

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

		self.rsa_public_key, self.rsa_private_key = (pub_key, priv_key)
		return True

	def scrypt(self, salt):
		backend = default_backend()
		return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1, backend=backend)

	def calculate_bit_commitment(self, hand, salt=None):
		SALT_SIZE = 16
		hand_str = str(hand).replace(" ", "")

		if salt == None:
			salt = os.urandom(SALT_SIZE)

		kdf = self.scrypt(salt)
		bin_hand = bytes(hand_str.encode())

		try:
			key = kdf.derive(bin_hand)

		except TypeError:
			logger.error('Variable bin_hand type is {} and not bytes.'.format(type(bin_hand)))
			return False

		else:
			key_str = b2a_base64(key).decode()
			salt_str = b2a_base64(salt).decode()
			HALF_SIZE = int(len(salt_str) / 2)

			private_key = self.load_private_key(base64.b64decode(self.rsa_private_key.encode()))
			public_key_pem = base64.b64decode(self.rsa_public_key.encode()).decode()
			
			bit_commitment_values = (key_str, salt_str[:HALF_SIZE])
			bit_commmitment_signature = base64.b64encode(self.rsa_signing(self.concatenate(bit_commitment_values).encode(), private_key)).decode()

			commitment_reveal_values = (hand_str, salt_str[HALF_SIZE:])
			commitment_reveal_signature = base64.b64encode(self.rsa_signing(self.concatenate(commitment_reveal_values).encode(), private_key)).decode()
			
			self.bit_commitment = bit_commitment_values, bit_commmitment_signature, public_key_pem
			self.commitment_reveal = commitment_reveal_values, commitment_reveal_signature

			return True

	def concatenate(self, tuple_elements):
		return tuple_elements[0]+tuple_elements[1]

	def verify_bit_commitment_signature(self, bit_commitment):
		bit_commitment_values, signature, pub_key_pem = bit_commitment
		public_key = self.load_public_key(pub_key_pem.encode())
		return self.rsa_signature_verification(base64.b64decode(signature.encode()), self.concatenate(bit_commitment_values).encode() , public_key) 

	def verify_commitment_reveal(self, bit_commitment, commitment_reveal):
		KEY = 0
		HAND = 0
		SALT = 1

		bit_commitment_values, bit_commitment_signature, pub_key_pem = bit_commitment
		commitment_reveal_values, commitment_reveal_signature = commitment_reveal
		public_key = self.load_public_key(pub_key_pem.encode())
		flag = self.rsa_signature_verification(base64.b64decode(commitment_reveal_signature.encode()), self.concatenate(commitment_reveal_values).encode(), public_key)

		if not flag:
			logger.warning('Signature mismatch from commitment_reveal.')
			return False

		salt_str = bit_commitment_values[SALT]+commitment_reveal_values[SALT]
		salt = a2b_base64(salt_str.encode())

		key_str = bit_commitment_values[KEY]
		key = a2b_base64(key_str.encode())
		
		hand_str = commitment_reveal_values[HAND]

		kdf = self.scrypt(salt)
		bin_hand = bytes(hand_str.encode())

		try:
			kdf.verify(bin_hand, key)
		except exceptions.InvalidKey:
			logger.warning('Key mismatch.')
			return False
		except exceptions.AlreadyFinalized:
			logger.warning('Verify method called more than once.')
			return False
		else:
			return True

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
			logger.warning('Commitment signature validation failed!')
			return False

		return True

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

	def generate_fernet_key(self):
		self.fernet_key = Fernet.generate_key()
		return True

	def fernet_encryption(self, bcard, key=None):
		if key == None:
			key = self.fernet_key
		f = Fernet(key)
		token = f.encrypt(bcard)
		return token

	def fernet_decryption(self, token, key):
		f = Fernet(key)
		token = f.decrypt(token)
		return token

	def fernet_decryption_rec(self, token, keys=None):
		if keys == None:
			keys = self.all_fernet_keys

		if len(keys) == 1:
			return self.fernet_decryption(token, keys[0])

		return self.fernet_decryption(self.fernet_decryption_rec(token, keys[1:]), keys[0])

	def encrypt_card(self, bcard):
		return self.fernet_encryption(bcard)

	def decrypt_card(self, e_card):
		return self.fernet_decryption_rec(e_card)