import base64
import os
from binascii import b2a_base64, a2b_base64, hexlify, unhexlify
from cryptography import exceptions
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import utils, rsa, padding


class Crypto():

	def __init__(self, mode="player"):
		self.rsa_public_key = None
		self.rsa_private_key = None

		if mode == "player":
			self.table_public_key = None
			self.bit_commitment = None
			self.commitment_reveal = None
			self.other_bit_commitments = {}
			self.other_commitments_reveal = {}
		elif mode == "table":
			self.players_public_keys = {}
			self.players_bit_commitments = {}
			self.players_commitments_reveal = {}


	def key_pair_gen(self, length):
		valid_lengths = [1024, 2048, 4096]

		if length not in valid_lengths:
			print("ERROR - Not a valid length!")
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

		self.rsa_public_key, self.rsa_private_key =	pub_key, priv_key
		return True

	def scrypt(self, salt):
		backend = default_backend()
		s = salt

		kdf = Scrypt(salt=s, length=32, n=2**15, r=8, p=1, backend=backend)

		return kdf


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
			print("Variable bin_hand type is {} and not bytes.".format(type(bin_hand)))
			return False
		except exceptions.AlreadyFinalized:
			print("Verify method called more than once.")
			return False

		else:
			key_str = b2a_base64(key).decode()
			salt_str = b2a_base64(salt).decode()
			HALF_SIZE = int(len(salt_str) / 2)

			self.bit_commitment, self.commitment_reveal = (key_str, salt_str[:HALF_SIZE]), (hand_str, salt_str[HALF_SIZE:])
			return True

	def verify_commitment_reveal(self, bit_commitment, commitment_reveal):
		salt_str = bit_commitment[1]+commitment_reveal[1]
		salt = a2b_base64(salt_str.encode())

		key_str = bit_commitment[0]
		key = a2b_base64(key_str.encode())
		
		hand_str = commitment_reveal[0]

		kdf = self.scrypt(salt)
		bin_hand = bytes(hand_str.encode())

		try:
			kdf.verify(bin_hand, key)
		except exceptions.InvalidKey:
			return False
		except exceptions.AlreadyFinalized:
			print("Verify method called more than once.")
			return False
		else:
			return True
