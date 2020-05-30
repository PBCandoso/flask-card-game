from card_game import Player
from utils import Crypto
import asyncio
import json
import base64
import binascii
import argparse
import coloredlogs, logging
import re
import os

logger = logging.getLogger('Player')

STATE_CONNECT = 0
STATE_READY = 1
STATE_NEW_ROUND = 2
STATE_GAME = 3
STATE_CLOSE = 4

class Game_Player():
	def __init__(self,sid,names):
		self.player = Player(names[0], auto=True)
		self.opponent_names = names[1:]
		self.sid = sid		# session id from socketio
		self.round_number = 0
		self.trick_number = 0
		self.state = STATE_READY

	def restart(self):
		self.player.score = 0
		self.player.tricksWon = []

	def log_state(self, received):
		#states = ['NEGOTIATION', 'DH', 'ROTATION','CONNECT', 'OPEN', 'DATA', 'CLOSE']
		#logger.info("State: {}".format(states[self.state]))
		logger.info("Received: {}".format(received))

	def on_frame(self, frame: str) -> None:
		"""
		Processes a frame (JSON Object)

		:param frame: The JSON Object to process
		:return:
		"""

		#logger.debug("Frame: {}".format(frame))

		try:
			message = json.loads(frame)
		except:
			logger.exception("Could not decode the JSON message")
			return

		mtype = message.get('type', None)
		self.log_state(mtype)

		if mtype == 'ROUND_UPDATE':
			logger.debug('ROUND_UPDATE')
			self.round_number = message['parameters']['round_number']
			logger.info('Current round: {}'.format(self.round_number))

			if self.state == STATE_READY:
				logger.debug('Starting first round')

			elif self.state == STATE_GAME:
				self.restart()
				logger.debug('Starting new round')

			self.state = STATE_GAME
			message = {'type': 'OK'}
			#self._send(message)

			return


		elif mtype == 'PASS_CARD_REQUEST' or mtype == 'PASS_CARD_REQUEST_ERROR':
			logger.debug('PASS_CARD_REQUEST')
			pass_card = self.process_pass_card_request()
			if pass_card is not None:
				self.player.removeCard(pass_card)
			message = {'type':'PASS_CARD_RESPONSE', 'parameters':{'card': pass_card}}
			#self._send(message)
			return

		elif mtype == 'DISTRIBUTE_PASSED_CARDS':
			logger.debug('DISTRIBUTE_PASSED_CARDS')
			cards = message['parameters']['cards']
			# DAR HIGHLIGHT ÀS CARTAS RECEBIDAS
			for card in cards:
				self.player.addCard(card)
			message = {'type': 'OK'}
			#self._send(message)
			return

		elif mtype == 'DISTRIBUTE_BIT_COMMITMENTS':
			logger.debug('DISTRIBUTE_BIT_COMMITMENTS')
			bit_commitments = message['parameters']['all_bit_commitments']
			#for name,commit in bit_commitments:
				#self.save_bit_commitments(name, commit)
			self.process_bit_commitments()
			return

		elif mtype == 'PLAY_CARD_REQUEST' or mtype == 'PLAY_CARD_REQUEST_ERROR':
			logger.debug('PLAY_CARD_REQUEST')
			play_card = self.process_play_card_request()
			if play_card is not None:
				self.player.removeCard(play_card)
			message = {'type':'PLAY_CARD_RESPONSE', 'parameters':{'card': play_card}}
			#self._send(message)
			return

		elif mtype == 'CARD_PLAYED':
			logger.debug('CARD_PLAYED')
			player = message['parameters']['player']
			card = message['parameters']['card']
			logger.info('{} played {}'.format(player, card))
			message = {'type': 'OK'}
			return

		elif mtype == 'TRICK_UPDATE':
			logger.debug('TRICK_UPDATE')
			trick = message['parameters']['current_trick']
			self.trick_number = message['parameters']['trick_number']
			winner = message['parameters']['trick_winner']
			#if winner == self.sid:
			#	SAVE TRICKS WON
			#	self.player.trickWon(trick)
			logger.info(trick)
			message = {'type': 'OK'}
			#self._send(message)
			return

		elif mtype == 'DISTRIBUTE_COMMITMENT_REVEALS':
			logger.debug('DISTRIBUTE_COMMITMENT_REVEALS')
			commitment_reveals = message['parameters']['all_commitment_reveals']
			#for name, commit in commitment_reveals:
				#self.save_commitment_reveals(name, commit)
			self.process_commitment_reveals()
			return

		elif mtype == 'MISMATCH_VERIFICATION':
			logger.debug('MISMATCH_VERIFICATION')
			message = {'type':'OK'}
			#self._send(message)
			return

		elif mtype == 'DISPLAY_SCORE':
			logger.debug('DISPLAY_SCORE')
			scores = message['parameters']['scores']
			message = {'type':'OK'}
			self.player.discardTricks()
			#self._send(message)
			return

		elif mtype == 'DISPLAY_WINNER':
			logger.debug('DISPLAY_WINNER')
			winner = message['parameters']['winner']
			message = {'type':'OK'}
			#self._send(message)
			self.state = STATE_CLOSE
			return

		elif mtype == 'OK':
			logger.warning("Ignoring message from server")
			return

		elif mtype == 'ERROR':
			logger.warning("Got error from server: {}".format(message.get('data', None)))
		
		else:
			logger.warning("Invalid message type")

		logger.debug('Closing')

	def process_shuffle_response(self, deck):
		new_deck, encryption_key = self.player.shuffle_deck(deck)
		return (new_deck, encryption_key)
		
	def process_pick_or_pass_response(self, deck):
		resp = self.player.pick_or_pass(deck)
		return resp

	def decrypt_hand(self, keys_list):
		self.player.decrypt_hand(keys_list)

	def process_bit_commitment_request(self):
		self.player.perform_bit_commitment()
		return self.player.crypto.bit_commitment

	def save_bit_commitments(self, bit_commit_dic):
		for name, bit_commit in bit_commit_dic:
			if name != self.player.name:
				self.player.crypto.other_bit_commitments[name] = bit_commit
	
	def process_bit_commitments(self):
		names = []
		for name, bit_commit in self.player.crypto.other_bit_commitments.items():
			if self.player.verify_bit_commitment_signature(bit_commit):
				names.append(name)

	def process_pass_card_request(self):
		return self.player.play(option='pass')

	def check_starter_request(self):
		return self.player.hand.contains2ofclubs

	def process_play_card_request(self, card=None):
		if card is not None:
			card = self.player.play(option='play', c=card)
		else:
			card = self.player.play(option='play')
			
		self.player.removeCard(card)
		return card

	def process_commitment_reveal_request(self):
		return self.player.crypto.commitment_reveal

	def save_commitment_reveals(self, commit_reveal_dic):
		for name, commit_reveal in commit_reveal_dic:
			if name != self.player.name:
				self.player.crypto.other_commitments_reveal[name] = commit_reveal

	def process_commitment_reveals(self):
		names = []
		for name, commit_reveal in self.player.crypto.other_commitments_reveal:
			if self.player.verify_commitment(self.player.crypto.other_bit_commitments[name], commit_reveal):
				names.append(name)
		logger.warning('MISMATCH_ERROR: {}'.format(names))
		message = {'type': 'OK'} if len(names)==0 else {'type': 'MISMATCH_ERROR', 'parameters':{'players': names}}
		#self._send(message)