from card_game import Deck, Card, Trick, Rank13, Suit
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
STATE_CARDS = 3
STATE_GAME = 4
STATE_VERIFY = 5 
STATE_RESULTS = 6
STATE_END = 7
STATE_CLOSE = 8

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
		if len(self.players) > 4:
			return ['full']
		else:
			if sid in self.players:
				return ['inroom']
			self.players.append(sid)
			randnames = random.choices(NAMES_LIST, k=4)
			self.sid_maped_with_players[sid] = Game_Player(sid, randnames)
			print("Player in room: ",self.players)
			return ['success', self.players]

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
			#ALL_ACK=1
			if self.ack == ALL_ACK:
				self.ack = 0

				if self.state == STATE_READY:
					# sent before: READY or DISPLAY_SCORE
					#self.names_maped = {self.players[i]:self.names[i] for i in range(len(self.players))}
					self.state = STATE_NEW_ROUND
					self.new_round()
					message = {'type': 'ROUND_UPDATE', 'round': self.round_num}
					return message ,'broadcast'

				if self.state == STATE_NEW_ROUND:
					print("NEW ROUND")
					# sent before: ROUND_UPDATE
					sid = random.choices(self.players)[0]

					self.players_shuffle()
					self.players_card_distribution()
					self.players_decrypt()


					print(self.round_num)
					self.players_make_commitments()
					self.save_bit_commitments()
					self.distribute_bit_commitments()
					self.players_process_commitments_signatures()
					self.state = STATE_CARDS
					
					return {'type':'ACK'},'broadcast'
				
				
				elif self.state == STATE_CARDS:
					print("CARDS")
					self.state = STATE_GAME
					message = {'type': 'GET_CARDS'}
					return message,'broadcast'

				elif self.state == STATE_GAME:
					print("GAME")
					# First trick
					if self.trick_num == 0:
						sid = self.get_starter()
						self.current_trick = Trick()
						self.trick_num += 1
						logger.info('Playing trick number: {}'.format(self.trick_num))

						self.trick_winner = [e for e,v in enumerate(self.players) if v == sid][0]

						message = {'type':'PLAY_CARD_REQUEST', 'parameters':{'card': '2c'}}
						return message, sid


					#send before: CARD_
					# NEXT: COMPLETE THE TRICK
					elif self.current_trick.cardsInTrick < 4:
						self.shift += 1
						next_sid = self.get_current_player_sid()
						message = {'type':'PLAY_CARD_REQUEST'}

						return message,next_sid

					# NEXT: TRICK_UPDATE
					elif self.current_trick.cardsInTrick == 4:
						self.evaluate_trick()

						if self.trick_winner not in self.scores:
							self.scores[self.trick_winner] = 0

						self.scores[self.trick_winner] += self.current_trick.points
						
						message = {'type': 'TRICK_UPDATE', 'parameters':{'trick_number': self.trick_num, 'trick_winner': self.trick_winner}}
						return message, 'broadcast'

					# NEXT: NEW TRICK
					elif self.trick_num < TOTAL_TRICKS:
						print("NEW TRICK")
						self.shift = 0
						logger.info('Playing trick number: {}'.format(self.trick_num))
						message = {'type': 'PLAY_CARD_REQUEST'}
						sid = self.sid_maped_with_players.get(self.trick_winner)
						return message,sid

					# NEXT: REVEAL COMMITMENTS
					else:
						print("REVEAL")
						self.save_commitment_reveals()
						self.distribute_commitments_reveal()
						self.players_process_commitments_reveal()

						self.state = STATE_VERIFY


				elif self.state == STATE_VERIFY:
					# sent before: DISTRIBUTE_COMMITMENT_REVEALS

					self.state = STATE_RESULTS
					self.handle_scoring()
					message = {'type': 'DISPLAY_SCORES', 'parameters':{'scores': self.total_scores}}
					#self._send(message)

					# The game will end. Someone lost
					if self.losing_player[0] is not None and self.losing_player[1] >= MAX_SCORE:
						self.state = STATE_RESULTS
					else:
						self.state = STATE_NEW_ROUND
						self.new_round()
						message = {'type': 'ROUND_UPDATE', 'parameters':{'round_number': self.round_num}}
						#self._send(message)

				elif self.state == STATE_RESULTS:
					# sent before: DISPLAY_SCORE

					self.state = STATE_END
					winner = self.get_winner()
					message = {'type': 'DISPLAY_WINNER', 'parameters':{'winner': winner}}
					return message, 'broadcast'

				elif self.state == STATE_END:
					# sent before: DISPLAY_WINNER
					
					'''

						Save results to DB
						Close everything
		
					'''
					#self.transport.close()
					# END		

			else:
				return {'data':'WAITING FOR PLAYERS'},'reply'


		elif mtype == 'SIGNATURE_FAILED':
			logger.debug('SIGNATURE_FAILED')

			return

		elif mtype == 'PLAY_CARD_RESPONSE':
			logger.debug('PLAY_CARD_RESPONSE')
			msgcard = message['parameters']['card']
			play_card = self.map_to_card(msgcard)
			sid = self.get_current_player_sid()

			if not sid == sender_id:
				# not their turn
				return {'type': 'WAIT_TURN'},'reply'

			if not self.eval_card_played(play_card):
				# card not accepted; repeats request
				if self.trick_num == 1 and self.shift == 0:
					message = {'type':'PLAY_CARD_REQUEST_ERROR', 'parameters':{'card': '2c'}}
				else:
					message = {'type':'PLAY_CARD_REQUEST_ERROR'}
				return message,'reply'

			else:
				# card accepted; advances
				self.current_trick.addCard(play_card, self.get_current_player_index())
				logger.debug('Current table: {}'.format(self.current_trick))
				
				# NEXT: CARD_PLAYED
				if self.current_trick.cardsInTrick <= 4:
					message = {'type': 'CARD_PLAYED', 'parameters':{'player':sid, 'card':{'rank': play_card.rank.__str__(), 'suit': play_card.suit.__str__()}}}
					
				return message,'broadcast'

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

		elif mtype == 'CARDS_REQUEST':
			hand = self.sid_maped_with_players[sender_id].player.hand
			message = {'type':'CARDS_RESPONSE','cards': hand.as_list()}
			return message,'reply'

		else:
			logger.warning("Invalid message type: {}".format(message['type']))

	def players_shuffle(self):
		# every player shuffles (and encrypts) the deck
		for sid in self.players:
			self.deck, cypher = self.sid_maped_with_players[sid].process_shuffle_response(self.deck)
			self.deck_ciphers.append(cypher)

	def players_card_distribution(self):
		# distributes cards
		while self.deck.size() > 0:
			for sid in self.sid_maped_with_players.keys():
				newdeck = self.sid_maped_with_players[sid].process_pick_or_pass_response(self.deck)
				if not newdeck:
					break

	def players_decrypt(self):
		for sid in self.players:
			self.sid_maped_with_players[sid].decrypt_hand(self.deck_ciphers)

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
					self.sid_maped_with_players[sid1].player.crypto.other_bit_commitments[self.sid_maped_with_players[sid2].player.name] = self.sid_maped_with_players[sid2].player.crypto.bit_commitment

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

	def get_starter(self):
		for sid,player in self.sid_maped_with_players.items():
			if player.check_starter_request():
				return sid

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
		self.to_be_passed = [n for n in range(4)]
		self.passing_cards = [[], [], [], []]
		self.shift = 0
		logger.info('New Round')
		logger.info('Round: {}'.format(self.round_num))

	def get_current_player_index(self):
		winner = [e for e,w in enumerate(self.players) if e == self.trick_winner][0]
		return (winner + self.shift) % len(self.players)

	def get_current_player_sid(self):
		return self.players[self.get_current_player_index()]

	def map_to_card(self, map):
		# Create card from str
		suits = ["c", "d", "s", "h"]
		ranks = [-1, -1, "2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"]
		return Card(Rank13(ranks.index(map['rank'])),Suit(suits.index(map['suit'])))

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