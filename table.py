from card_game import Deck, Card, Trick
from utils import Crypto
from player import Game_Player
import asyncio
import json
import base64
import binascii
import argparse
import coloredlogs, logging
import os
import random

logger = logging.getLogger('Table')
level = logging.INFO
logger.setLevel(level)

STATE_CONNECT = 0
STATE_READY = 1
STATE_NEW_ROUND = 2
STATE_SHUFFLE = 3
STATE_DECRYPTION = 4
STATE_COMMITMENT = 5
STATE_PASS = 6
STATE_GAME = 7
STATE_VERIFY = 8 
STATE_RESULTS = 9
STATE_END = 10
STATE_CLOSE = 11
ALL_ACK = 4

'''
Change auto to False if you would like to play the game manually.
This allows you to make all passes, and plays for all four players.
When auto is True, passing is disabled and the computer plays the
game by "guess and check", randomly trying moves until it finds a
valid one.
'''
auto = False

TOTAL_TRICKS = 13
MAX_SCORE = 100

QUEEN = 12
UNDEFINED = -1
CLUBS = 0
DIAMONDS = 1
SPADES = 2
HEARTS = 3
CARDS_TO_PASS = 3

NAMES_LIST = ['Alves', 'Barbosa', 'Carvalho', 'Domingues', 'Esteves', 
		'Ferreira', 'Gomes', 'Henriques', 'Imaginário', 'Jesus', 'Lopes', 
		'Martins', 'Nunes', 'Oliveira', 'Pereira', 'Queirós', 'Rodrigues', 
		'Silva', 'Teixeira', 'Unas', 'Vieira', 'Zé']

class Hearts_Table():
	
	def __init__(self):
		
		self.round_num = 0
		self.passes = [1, -1, 2, 0] # left, right, across, no pass
		self.losing_player = None, None
		self.crypto = Crypto("table")

		self.players = [] #contains sid of each player
		self.ack = 0
		self.needs_to_do_something = self.players	#to be emptied and refilled
		self.total_scores = {}
		self.sid_maped_with_players = {}
		self.state = STATE_READY

		'''
		Player physical locations:
		Game runs clockwise
			C
		B		D
			A
		'''

	def log_state(self, received):
		logger.info("Received: {}".format(received))

	def join(self,sid):
		print("Player in room: ",self.players)
		if len(self.players) > 4:
			return ['full']
		else:
			if sid in self.players:
				return ['inroom']
			self.players.append(sid)
			randnames = random.choices(NAMES_LIST, k=len(self.players))
			self.sid_maped_with_players[sid] = Game_Player(sid, randnames)
			return ['success', randnames, len(self.players)-1]

	def on_frame(self, sid, frame):
		"""
		Processes a frame (JSON Object)

		:param frame: The JSON Object to process
		:return:
		"""

		#logger.debug("Frame: {}".format(frame))

		try:
			message = frame
		except:
			logger.exception("Could not decode the JSON message")
			return

		mtype = message.get('type', None)
		self.log_state(mtype)

		sender_id = sid

		if mtype == 'OK':
			logger.debug('OK')
			self.ack += 1

			'''
			if everyone acknowldges (ACK=4); 
			searches for actual state and updates and/or send a message
			'''
			logger.debug('{} - {}'.format(mtype, self.state))
			ALL_ACK=1
			if self.ack == ALL_ACK:
				self.ack = 0

				if self.state == STATE_READY:
					# sent before: READY or DISPLAY_SCORE
					#self.names_maped = {self.players[i]:self.names[i] for i in range(len(self.players))}
					self.state = STATE_NEW_ROUND
					self.new_round()
					message = {'type': 'ROUND_UPDATE', 'round': self.round_num}
					return message,True

				if self.state == STATE_NEW_ROUND:
					# sent before: ROUND_UPDATE
					#message = {'type': 'SHUFFLE_REQUEST', 'parameters':{'deck': self.deck.as_list()}}
					sid = random.choices(self.players)

					self.players_shuffle()
					self.players_card_distribution()
					self.players_decrypt()

					self.state = STATE_PASS

					if (self.trick_num % 4) != 0: # don't pass every fourth hand
						message = {'type': 'PASS_CARD_REQUEST'}
						#self._send(message, sid)
					else:
						self.players_make_commitments()
						self.save_bit_commitments()
						self.distribute_bit_commitments()
						self.players_process_commitments_signatures()
						self.state = STATE_COMMITMENT

						#self._send(message)

				elif self.state == STATE_PASS:
					# sent before: DISTRIBUTE_PASSED_CARDS
					self.players_make_commitments()
					self.save_bit_commitments()
					self.distribute_bit_commitments()
					self.players_process_commitments_signatures()
						
					self.state = STATE_COMMITMENT
					message = {'type': 'BIT_COMMITMENT_REQUEST'}
					#self._send(message)

				elif self.state == STATE_COMMITMENT:
					# sent before: DISTRIBUTE_BIT_COMMITMENTS
					
					self.state = STATE_GAME
					message = {'type': 'STARTER_REQUEST'}
					#self._send(message)

				elif self.state == STATE_GAME:
					#send before: TRICK_UPDATE

					# NEXT: NEW TRICK
					if self.trick_num < TOTAL_TRICKS:
						logger.info('Playing trick number: {}'.format(self.trick_num))
						message = {'type': 'PLAY_CARD_REQUEST'}
						sid = self.players[self.trick_winner]
						#self._send(message, sid)

					# NEXT: REVEAL COMMITMENTS
					else:
						self.save_commitment_reveals()
						self.distribute_commitments_reveal()
						self.players_process_commitments_reveal()

						self.state = STATE_VERIFY
						message = {'type': 'COMMITMENT_REVEAL_REQUEST'}
						#self._send(message)


				elif self.state == STATE_VERIFY:
					# sent before: DISTRIBUTE_COMMITMENT_REVEALS

					self.state = STATE_RESULTS
					self.handle_scoring()
					message = {'type': 'DISPLAY_SCORES', 'parameters':{'scores': self.total_scores}}
					#self._send(message)

					# The game will end. Someone lost
					if self.losing_player[0] is None and self.losing_player[1] >= MAX_SCORE:
						self.state = STATE_RESULTS
					else:
						self.state == STATE_NEW_ROUND
						self.new_round()
						message = {'type': 'ROUND_UPDATE', 'parameters':{'round_number': self.round_num}}
						#self._send(message)

				elif self.state == STATE_RESULTS:
					# sent before: DISPLAY_SCORE

					self.state = STATE_END
					winner = self.get_winner()
					message = {'type': 'DISPLAY_WINNER', 'parameters':{'winner': winner}}
					#self._send(message)


				elif self.state == STATE_END:
					# sent before: DISPLAY_WINNER
					
					'''

						Save results to DB
						Close everything
		
					'''
					#self.transport.close()
					# END		

			else:
				return {'data':'WAITING FOR PLAYERS'}


		elif mtype == 'PASS_CARD_RESPONSE':
			logger.debug('PASS_CARD_RESPONSE')
			pass_card = message['parameters']['card']
			sender_sid = sid
			flag, pass_to = self.pass_card(index=self.players.index(sender_sid), pass_card=pass_card)

			if not flag:
				# card not accepted; repeats request
				message = {'type':'PASS_CARD_REQUEST_ERROR'}
				#self._send(sid)

			else:
				# card accepted; advances
				logger.debug('Passing cards: {}'.format(self.passing_cards))

				# NEXT: ANOTHER CARD TO PASS
				if len(self.passing_cards[pass_to]) < CARDS_TO_PASS:
					message = {'type':'PASS_CARD_REQUEST'}
					#self._send(sid)

				# NEXT: DISTRIBUTE_PASSED_CARDS
				elif list(set([len(n) for n in self.passing_cards]))[0] == CARDS_TO_PASS:
					self.distribute_passed_cards()

				# NEXT: CARD TO PASS - NEW PLAYER
				else:
					#self.needs_to_do_something.pop(sid)
					#sid = random.choices(self.players)
					message = {'type':'PASS_CARD_REQUEST'}
					#self._send(message, sid)

			return


		elif mtype == 'SIGNATURE_FAILED':
			logger.debug('SIGNATURE_FAILED')

			return

		elif mtype == 'STARTER_RESPONSE':
			logger.debug('STARTER_RESPONSE')
			if message['parameters']['value']:
				self.current_trick = Trick()
				self.trick_num += 1
				logger.info('Playing trick number: {}'.format(self.trick_num))

				#sender_sid = sid
				#self.trick_winner = self.players.index(sender_sid)

				message = {'type':'PLAY_CARD_REQUEST', 'parameters':{'card': '2c'}}
				sid = self.get_current_player_sid()
				#self._send(message, sid)
			return

		elif mtype == 'PLAY_CARD_RESPONSE':
			logger.debug('PLAY_CARD_RESPONSE')
			play_card = message['parameters']['card']
			sid = self.get_current_player_sid()

			if not self.eval_card_played(play_card):
				# card not accepted; repeats request
				if self.trick_num == 1 and self.shift == 0:
					message = {'type':'PLAY_CARD_REQUEST_ERROR', 'parameters':{'card': '2c'}}
				else:
					message = {'type':'PLAY_CARD_REQUEST_ERROR'}
				#self._send(message, sid)


			else:
				# card accepted; advances
				self.current_trick.addCard(play_card, self.get_current_player_index())
				logger.debug('Current table: {}'.format(self.current_trick))
				self.shift += 1
				next_sid = self.get_current_player_sid()

				if len(self.current_trick) != 4:
					message = {'type':'PLAY_CARD_REQUEST'}
					#self._send(message, next_sid)

				else:
					# NEXT: TRICK UPDATE
					self.evaluate_trick()
					self.shift = 0
					message = {'type': 'TRICK_UPDATE', 'parameters':{'trick_number': self.trick_num, 'current_trick': self.current_trick, 'trick_winner': self.trick_winner}}
					self.scores[self.trick_winner] += self.current_trick.points
					#self._send(message)
			return


		elif mtype == 'MISMATCH_ERROR':
			logger.debug('MISMATCH_ERROR')
			#sender_sid = sid
			possible_cheaters_names = message['parameters']['players']
			possible_cheaters_sid = [sid for sid,names in self.sid_maped_with_players.items() 
											for pcheater in possible_cheaters_names 
												if pcheater in names
									]
			# eval mismatch
			eval_cheaters = [self.verify_commitment(sid) for sid in possible_cheaters_sid]
			ret_dic = {possible_cheaters_names[i]:eval_cheaters[i] for i in range(len(eval_cheaters))}
			
			if all(eval_cheaters):
				# both will have penalty on score
				pass
			elif eval_cheaters[0]:
				# the first has penalty on score
				pass
			elif eval_cheaters[1]:
				# the second has penalty on score
				pass
			else:
				# None has penalty on score
				pass
				
			
			message = {'type':'MISMATCH_VERIFICATION', 'parameters':{'value': ret_dic}}
			#self._send(message, sender_sid)
			return

		else:
			logger.warning("Invalid message type: {}".format(message['type']))
			ret = False

		if not ret:
			try:
				self._send({'type': 'ERROR', 'message': 'Check server'})
			except:
				pass # Silently ignore

			logger.info("Closing transport")

			self.state = STATE_CLOSE
			#self.transport.close()

	def players_shuffle(self):
		# every player shuffles (and encrypts) the deck
		for sid in self.players:
			self.deck, cypher = self.sid_maped_with_players[sid].player.shuffle_deck(self.deck)
			self.deck_ciphers.append(cypher)

	def players_card_distribution(self):
		# distributes cards
		while self.deck.size() > 0:
			for sid in self.sid_maped_with_players.keys():
				if not self.sid_maped_with_players[sid].player.pick_or_pass(self.deck):
					break

	def players_decrypt(self):
		for sid in self.players:
			self.sid_maped_with_players[sid].player.decrypt_hand(self.deck_ciphers)

	def players_make_commitments(self):
		for sid in self.sid_maped_with_players.keys():
			self.sid_maped_with_players[sid].player.perform_bit_commitment()

	def save_bit_commitments(self):
		for sid in self.sid_maped_with_players.keys():
			self.save_bit_commitment(sid, self.sid_maped_with_players[sid].player.crypto.bit_commitment)
			logger.info("{} bit commitment: {}".format(sid, self.sid_maped_with_players[sid].player.crypto.bit_commitment))

	def distribute_bit_commitments(self):
		for i, sid1 in enumerate(self.sid_maped_with_players.keys()):
			for j, sid2 in enumerate(self.sid_maped_with_players.keys()):
				if sid2 != sid1:														# pass the right name
					self.sid_maped_with_players[sid1].player.crypto.other_bit_commitments[self.self.sid_maped_with_players[sid2].name] = self.sid_maped_with_players[sid2].crypto.bit_commitment

	def players_process_commitments_signatures(self):
		for sid in self.sid_maped_with_players.keys():
			self.sid_maped_with_players[sid].process_bit_commitments()

	def save_commitment_reveals(self):
		for sid in self.sid_maped_with_players.keys():
			self.save_commitment_reveal(sid, self.sid_maped_with_players[sid].player.crypto.commitment_reveal)
			logger.info("{} bit commitment: {}".format(sid, self.sid_maped_with_players[sid].player.crypto.commitment_reveal))

	def distribute_commitments_reveal(self):
		for i, sid1 in enumerate(self.sid_maped_with_players.keys()):
			for j, sid2 in enumerate(self.sid_maped_with_players.keys()):
				if sid2 != sid1:													# save the name here for the player
					self.sid_maped_with_players[sid1].crypto.other_commitments_reveal[self.players[j].name] = self.sid_maped_with_players[sid2].crypto.commitment_reveal

	def players_process_commitments_reveal(self):
		for sid in self.sid_maped_with_players.keys():
			self.sid_maped_with_players[sid].process_commitment_reveals()

	def get_winner(self):
		min_score = 1000 # impossibly high
		winner = None
		for sid, score in self.total_scores:
			if score < min_score:
				winner = sid
				min_score = score
		return winner

	def check_got_all(self, got_em_all):
		for sid,score in self.scores:
			if got_em_all[0]:
				if sid != got_em_all[1]:
					score = 26
				else:
					score = 0

	def handle_scoring(self):
		p, highest_score = None, 0
		got_em_all = (False, None)
		for sid,score in self.scores:
			if score == 26:
				got_em_all = (True, sid)

		self.check_got_all(got_em_all)

		logger.info('Scores: ')
		for sid, score in self.scores:
			self.total_scores[sid] += score

			logger.info('{}: {}'.format(sid, str(self.total_scores[sid])))
			score = 0
			if self.total_scores[sid] > highest_score:
				p = sid
				highest_score = self.total_scores[sid]
			self.losing_player = p,score

	def new_round(self):
		self.deck = Deck(game='Hearts')
		self.deck_ciphers = []
		self.round_num += 1
		self.trick_num = 0 # initialization value such that first round is round 0
		self.trick_winner = UNDEFINED # saves the index
		self.hearts_broken = False
		self.scores = {}
		self.passing_cards = [[], [], [], []]
		self.shift = 0
		logger.info('New Round')
		logger.info('Round: {}'.format(self.round_num))

	def get_current_player_index(self):
		return (self.trick_winner + self.shift) % len(self.players)

	def get_current_player_sid(self):
		return self.players[self.get_current_player_index()]

	def evaluate_trick(self):
		self.trick_winner = self.current_trick.winner
		sid = self.players[self.trick_winner]
		self.print_current_trick()
		logger.info(sid + 'won the trick.')
		# print('Making new trick')
		self.current_trick = Trick()
		self.shift = 0
		if self.trick_num < TOTAL_TRICKS-1:
			logger.info(self.current_trick.suit)

	def distribute_passed_cards(self):
		for i,passed in enumerate(self.passing_cards):
			message = {'type':'DISTRIBUTE_PASSED_CARDS', 'parameters':{'cards':passed}}
			sid = self.players[i]
			#self._send(message, sid)
		self.passing_cards = [[], [], [], []]

	def save_bit_commitment(self, sid, bit_commitment):
		self.crypto.players_bit_commitments[sid] = bit_commitment
		logger.info("{} bit commitment: {}".format(sid, self.crypto.players_bit_commitments[sid]))
	
	def verify_bit_commitment_signature(self, sid):
		if self.crypto.verify_bit_commitment_signature(self.crypto.players_bit_commitments[sid]):
			logger.info("Signature match! -> {0}".format(sid))
			return True
		
		logger.warning("Signature mismatch!!! -> {0}".format(sid))
		return False

	def save_commitment_reveal(self, sid, commitment_reveal):
		self.crypto.players_commitments_reveal[sid] = commitment_reveal
		logger.info("{} bit commitment: {}".format(sid, self.crypto.players_commitments_reveal[sid]))
		
	def verify_commitment(self, sid):
		if self.crypto.verify_commitment_reveal(self.crypto.players_bit_commitments[sid], self.crypto.players_commitments_reveal[sid]):
			logger.info("Commitment match! -> {0}".format(sid))
			return True

		logger.warning("Commitment mismatch!!! -> {0}".format(sid))
		return False
	
	def print_current_trick(self):
		trick_str = '\nCurrent table:\n'
		trick_str += "Trick suit: " + self.current_trick.suit.__str__() + "\n"
		for i, card in enumerate(self.current_trick.trick):
			#logger.debug("Debug: {} {}".format(i, self.currentTrick.trick))
			if type(self.current_trick.trick[i]) is Card:
				trick_str += self.players[i] + ": " + str(card) + "\n"
			else:
				trickStr += self.players[i] + ": None\n"
		logger.info(trick_str)

	def eval_card_played(self, card_played):
		# the rules for what cards can be played
		# card set to None if it is found to be invalid
		if card_played is not None:
			
			# if it is not the first trick and no cards have been played,
			# set the first card played as the trick suit
			if self.trick_num > 1 and self.current_trick.cardsInTrick == 0:
				self.current_trick.setTrickSuit(card_played)
			return True

		return False

	def pass_card(self, index, pass_card):
		logger.info('passcard')
		pass_to = self.passes[self.round_num] # how far to pass cards
		pass_to = (index + pass_to) % len(self.players) # the index to which cards are passed
		
		if pass_card is not None:
			# add card to passed cards
			self.passing_cards[pass_to].append(pass_card)
			return True, pass_to

		return False, None

'''
	def process_close(self, message: str) -> bool:
		"""
		Processes a CLOSE message from the client.
		This message will trigger the termination of this session

		:param message: The message to process
		:return: Boolean indicating the success of the operation
		"""
		logger.debug("Process Close: {}".format(message))
		self.transport.close()

		self.state = STATE_CLOSE
		#logger.info("Closed")

		return True
'''