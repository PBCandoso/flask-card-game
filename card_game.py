import random
from utils import Crypto

class Deck:
	def __init__(self, game="Hearts", deck=None, mode="normal"):
		self._deck = []
		self.__numSuits = 4
		self.__minRank = 2
		self.__maxRank = -1
		self.__game = game

		if deck != None and mode=="encrypted":
			self.addCards(deck)

		if self._deck == []:
			if self.__game == "Hearts":
				self.__maxRank = 14
			elif self.__game == "Sueca":
				self.__maxRank = 11
			else:
				raise Exception("Game not implemented")

		
			for suit in range(0, self.__numSuits):
				for rank in range(self.__minRank,self.__maxRank+1):
					if self.__game == "Hearts": 
						self._deck.append(Card(Rank13(rank), Suit(suit)))
					elif self.__game == "Sueca": 
						self._deck.append(Card(Rank10(rank), Suit(suit)))


	def __str__(self):
		deckStr = ''
		for i in range(self.size()):
			deckStr += self._deck[i].__str__() 
			if i != self.size()-1:
				deckStr += ', '
		return deckStr

	def shuffle(self):
		random.shuffle(self._deck)

	def shuffle_return(self):
		return random.sample(self._deck, self.size())

	def deal_top(self):
		return self._deck.pop(0)

	def deal_bottom(self):
		return self._deck.pop()

	def deal_rand(self):
		#if self.size()==0:
		#	print('EMPTY DECK!')
		if self.size() == 1:
			return self._deck.pop(0)
		return self._deck.pop(random.randint(0, self.size()-1))

	def switch(self, card):
		ret_card = self.deal_rand()
		self.addCards([card])

		return ret_card

	def sort(self):
		self._deck.sort()

	def size(self):
		return len(self._deck)

	def addCards(self, cards):
		self._deck += cards

	def __iter__(self):
		''' Returns the Iterator object '''
		return DeckIterator(self)

class DeckIterator:
	''' Iterator class '''
	def __init__(self, deck):
		# Deck object reference
		self._deck = deck
		# member variable to keep track of current index
		self._index = 0
 
	def __next__(self):
		''''Returns the next value from deck object's lists '''
		if self._index < len(self._deck._deck) :
			result = self._deck._deck[self._index]
			self._index +=1
			return result
		# End of Iteration
		raise StopIteration

class Card:
	def __init__(self, rank, suit):
		self.rank = rank
		self.suit = suit

	def eval(self, other):
		clause1 = self.rank > other.rank and self.suit == other.suit
		clause2 = self.suit.isTrump == True and other.suit.isTrump == False
		return self if (clause1 or clause2) else other

	def __lt__(self, other):
		return (self.rank < other.rank or (self.rank == other.rank and self.suit < other.suit))

	def __ge__(self, other):
		return not (self < other)

	def __gt__(self, other):
		return (self.rank > other.rank or (self.rank == other.rank and self.suit > other.suit))

	def __le__(self, other):
		return not (self > other)

	def __eq__(self, other):
		return self.rank == other.rank and self.suit == other.suit

	def __ne__(self, other):
		return not (self == other)

	def __str__(self):
		return self.rank.__str__() + self.suit.__str__()

	def __bytes__(self):
		return bytes(self.__str__(), encoding='utf-8')

	def encode(self):
		return self.__str__().encode('utf-8')

	def decode(self):
		return self.__bytes__().decode('utf-8')

#Suit identification (iden, trump); Trump is a boolean variable
UNDEFINED = -1
CLUBS = 0
DIAMONDS = 1
SPADES = 2
HEARTS = 3

class Suit:
	def __init__(self, iden, trump=False):
		self.iden = iden
		self.isTrump = trump
		self.__string = ''
		suits = ["c", "d", "s", "h"]

		if iden == UNDEFINED:
			self.__string = "Undefined"
		elif iden <= 3:
			self.__string = suits[iden]
		else:
			raise Exception('Suit out of bound: Suit index must be between 0 and 3.')

	def __eq__(self, other):
		return self.iden == other.iden

	def __ne__(self, other):
		return not (self == other)

	def __lt__(self, other):
		return self.iden < other.iden

	def __gt__(self, other):
		return self.iden > other.iden

	def __ge__(self, other):
		return not (self < other)

	def __le__(self, other):
		return not (self > other)

	def __str__(self):
		return self.__string


class Rank:
	def __init__(self, rank):
		self._string = ''
		self.__value = rank	
		
	def __lt__(self, other):
		return self.__value < other.__value

	def __ge__(self, other):
		return not (self < other)

	def __gt__(self, other):
		return self.__value > other.__value

	def __le__(self, other):
		return not (self > other)

	def __eq__(self, other):
		return self.__value == other.__value

	def __ne__(self, other):
		return not (self == other)

	def __str__(self):
		return self._string


class Rank13(Rank):
	def __init__(self, rank):
		super().__init__(rank)
		self.value = rank
		strings = ["J", "Q", "K", "A"]

		'''
		Card Ranks by numbers 2-14, [2-10]+'J'+'Q'+'K'+'A'
		14 = Ace ; 2 = Two
		'''
		if rank == -1:
			self._string = "Undefined"
		elif rank >= 2 and rank <= 10:
			self._string = str(rank)
		elif rank > 10 and rank <= 14:
			self._string = strings[rank - 11]
		else:
			raise Exception('Rank out of bond: Rank index must be between 2 and 14')

class Rank10(Rank):
	def __init__(self, rank):
		super().__init__(rank)
		strings = ["Q", "J", "K", "7", "A"]

		'''
		Card Ranks by numbers 2-11, [2-6]+'Q'+'J'+'K'+'7'+'A'
		11 = Ace ; 2 = Two
		'''
		if rank == -1:
			self._string = "Undefined"
		elif rank >= 2 and rank <= 6:
			self._string = str(rank)
		elif rank > 6 and rank <= 11:
			self._string = strings[rank - 7]
		else:
			raise Exception('Rank out of bond: Rank index must be between 2 and 11')

class Hand:
	def __init__(self, n):
		self.__cardsPerPlayer = n		# 13 or 10 starting cards
		self.clubs = []
		self.diamonds = []
		self.spades = []
		self.hearts = []
		
		# create hand of cards split up by suit
		self.value = [self.clubs, self.diamonds, self.spades, self.hearts]

		self.contains2ofclubs = False

	def size(self):
		return len(self.clubs) + len(self.diamonds) + len(self.spades) + len(self.hearts)

	def addCard(self, card):
		if card.suit == Suit(CLUBS):
			if card.rank.value == 2:
				self.contains2ofclubs = True
			self.clubs.append(card)
		elif card.suit == Suit(DIAMONDS):
			self.diamonds.append(card)
		elif card.suit == Suit(SPADES):
			self.spades.append(card)
		elif card.suit == Suit(HEARTS):
			self.hearts.append(card)
		else:
			raise Exception('Invalid Card: Couldn\'t add card to Hand')

		if self.size() == self.__cardsPerPlayer:
			#print("Já tenho as cartas para jogar")
			for suit in self.value:
				suit.sort()

	def updateHand(self):
		self.value = [self.clubs, self.diamonds, self.spades, self.hearts]

	def getRandomCard(self, suit=UNDEFINED):
		SUITS = [CLUBS, DIAMONDS, SPADES, HEARTS]

		if trick_suit in SUITS:
			trick_suit = SUITS.index(trick_suit)
		else:
			trick_suit = UNDEFINED

		suits_in_hand = [i for i in [CLUBS, DIAMONDS, SPADES, HEARTS] if len(self.value[i]) > 0]	# suits with len > 0
		possib = suits_in_hand

		if trick_suit in suits_in_hand:
			possib = [trick_suit]

		idx = random.choice(possib)
		suit = self.value[idx]

		index = random.randint(0, len(suit)-1)

		return suit[index]

	def strToCard(self, card):
		if len(card) == 0: return None
		
		suits = ["c", "d", "s", "h"]
		suit = card[len(card)-1].lower() # get the suit from the string
		
		try:
			suitIden = suits.index(suit)
		except:
			print('Invalid suit')
			return None

		cardRank = card[0:len(card)-1] # get rank from string
		
		try:
			cardRank = cardRank.upper()
		except AttributeError:
			pass

		if self.__cardsPerPlayer == 13:
			# convert rank to int
			if cardRank == "J":
				cardRank = 11
			elif cardRank == "Q":
				cardRank = 12
			elif cardRank == "K":
				cardRank = 13
			elif cardRank == "A":
				cardRank = 14
			else:
				try:
					cardRank = int(cardRank)
				except:
					print("Invalid card rank: Card is not a number.")
					return None

		elif self.__cardsPerPlayer == 10:
			# convert rank to int
			if cardRank == "Q":
				cardRank = 7
			elif cardRank == "J":
				cardRank = 8
			elif cardRank == "K":
				cardRank = 9
			elif cardRank == '7':
				cardRank = 10
			elif cardRank == "A":
				cardRank = 11
			else:
				try:
					cardRank = int(cardRank)
				except:
					print("Invalid card rank: Card is not a number.")
					return None

		return cardRank, suitIden

	def containsCard(self, cardRank, suitIden):
		for card in self.value[suitIden]:
			if card.rank.value == cardRank:
				cardToPlay = card
					
				# remove cardToPlay from hand
				# self.value[suitIden].remove(card)
				
				# update hand representation
				# self.updateHand()
				return cardToPlay
		return None

	def playCard(self, card):
		cardInfo = self.strToCard(card)

		if cardInfo is None:
			return None
		
		cardRank, suitIden = cardInfo[0], cardInfo[1]
		
		# see if player has that card in hand
		return self.containsCard(cardRank, suitIden)

	def removeCard(self, card):
		suitId = card.suit.iden
		for c in self.value[suitId]:
			if c == card:
				if suitId == "clubs" and card.rank.value == 2:
					self.contains2ofclubs = False
				# print("Removing:", c.__str__())
				self.value[card.suit.iden].remove(c)
				self.updateHand()

	def hasSuit(self, suit):
		return len(self.value[suit]) > 0

	def hasOnlySuit(self, suit):
		return len(self.value[suit]) == self.size()

	def hasOnlyHearts(self):
		return self.hasOnlySuit(HEARTS)

	def __str__(self):
		handStr = ''
		for suit in self.value:
			for card in suit:
				handStr += card.__str__() + ' '
		return handStr

	def as_list(self):
		lst = []
		for suit in self.value:
			for card in suit:
				lst.append({'rank':card.rank.__str__(),'suit': card.suit.__str__()})
		return lst

class Encrypted_Hand:
	def __init__(self, n):
		self.__cardsPerPlayer = n
		self.value = []

	def add_encrypted_card(self, e_card):
		self.value.append(e_card)

	def remove_encrypted_card(self, e_card):
		return self.value.pop(self.value.index(e_card))
			
	def size(self):
		return len(self.value)

	def __str__(self):
		handStr = ''
		for e_card in self.value:
			handStr += e_card.__str__() + ' '
		return handStr

class Trick:
	def __init__(self, game="Hearts", n=4):
		self.game = game 			# Hearts or Sueca
		self.n = n 					# N players
		self.trick = [0] * self.n 	# Initializes a list of N zeros
		self.suit = Suit(UNDEFINED)
		self.cardsInTrick = 0
		self.points = 0
		self.highest = 0
		self.winner = UNDEFINED

		if self.game == "Hearts":
			self.highest = Card(Rank13(UNDEFINED),self.suit) # rank of the high trump suit card in trick
		elif self.game == "Sueca":
			self.highest = Card(Rank10(UNDEFINED), self.suit) # rank and suit of the high trump suit card in trick

	def reset(self):
		self.trick = [0] * self.n
		self.suit = Suit(UNDEFINED)
		self.cardsInTrick = 0
		self.points = 0
		self.winner = UNDEFINED

		if self.game == "Hearts":
			self.highest = Card(Rank13(UNDEFINED),self.suit) # rank  of the higher suit card in trick
		elif self.game == "Sueca":
			self.highest = Card(Rank10(UNDEFINED), self.suit) # rank and suit of the most valuable card in trick

	# def cardsInTrick(self):
	# 	count = 0
	# 	for card in self.trick:
	# 		if card is not 0:
	# 			count += 1
	# 	return count

	def setTrickSuit(self, card):
		self.suit = card.suit

	def addCard(self, card, index):
		if self.cardsInTrick == 0: # if this is the first card added, set the trick suit
			self.setTrickSuit(card)
			print('Current trick suit: {}'.format(self.suit))
		
		self.trick[index] = card
		self.cardsInTrick += 1

		if self.game == "Hearts":
			QUEEN = 12

			if card.suit == Suit(HEARTS):
				self.points += 1
			elif card == Card(Rank13(QUEEN), Suit(SPADES)):
				self.points += 13

		elif self.game == "Sueca":
			ACE = 11
			SEVEN = 10
			KING = 9
			JACK = 8
			QUEEN = 7

			if card.rank == Rank(ACE):
				self.points += 11
			elif card.rank == Rank(SEVEN):
				# Each Seven - 10 points
				self.points += 10
			elif card.rank == Rank(KING):
				# Each King - 4 points
				self.points += 4
			elif card.rank == Rank(JACK):
				# Each Jack - 3 points
				self.points += 3
			elif card.rank == Rank(QUEEN):
				# Each Queen - 2 points
				self.points += 2


		if self.cardsInTrick == 1 or card.eval(self.highest) == card:
			self.highest = card
			self.winner = index
					
		print("Highest: {}".format(self.highest))

class Player:
	def __init__(self, name, game="Hearts", auto=False):
		self.name = name
		self.crypto = Crypto()
		self.score = 0
		self.total_score = 0
		self.tricksWon = []
		self.autoplay = auto
		self.n = 13 if game == "Hearts" else 10
		
		print("{} {}".format(self.name, "generated asymmetric keys with sucess" if self.generate_asymmetric_keys() else "Failed to generate asymmetric keys"))

		self.encrypted_hand = Encrypted_Hand(self.n)
		self.hand = Hand(self.n)

	def shuffle_deck(self, deck):
		print("{} {}".format(self.name, "generated Fernet key with sucess" if self.generate_fernet_key() else "Failed to generate Fernet key"))

		### BEGIN ENCRYPT DECK ###
		new_cards = []
		for card in deck:
			#print(str(card))
			if type(card) == Card:
				card = bytes(card)
			new_cards += [self.encrypt_card(card)]
		#print(new_cards)		
		new_deck = Deck(deck=new_cards, mode="encrypted")
		### END ENCRYPT DECK ###
		#print(new_deck)
		new_deck.shuffle()
		return new_deck, self.crypto.fernet_key

	def deal_card(self, deck):
		return deck.deal_rand()

	def pick_or_pass(self, deck):
		decision_ch, decision_n = self.pick_or_pass_decision(deck)

		if decision_ch == 'empty':	
			return False
		elif decision_ch == 'pick':
			self.add_encrypted_card(self.deal_card(deck))
		elif decision_ch == 'pass' and decision_n > 0:
			cards_to_switch = random.sample(self.encrypted_hand.value, decision_n)

			for c in cards_to_switch:
				self.remove_encrypted_card(c)

			for n in range(decision_n):
				new_card = deck.switch(cards_to_switch[n])
				self.add_encrypted_card(new_card)

		return deck

	def pick_or_pass_decision(self, deck):
		p = 0.05
		maximum = self.encrypted_hand.size() if self.encrypted_hand.size() <= deck.size() else deck.size()
		n = random.randint(0, maximum)

		if self.encrypted_hand == []:
			return ('pick', 1)

		if deck.size() == 0:
			return ('empty', 0)

		if self.encrypted_hand.size() < self.n:
			choices_v = ('pick', 'pass')
			choices_p = (p, 1-p)
			ch = random.choices(choices_v, weights=choices_p)[0]

			return (ch, 1) if ch == 'pick' else (ch, n)
		
		return ('pass', n)

	def decrypt_hand(self, deck_ciphers):
		self.crypto.all_fernet_keys = deck_ciphers	
		for e_card in self.encrypted_hand.value:
			### BEGIN DECRYPT ###
			card_str = self.decrypt_card(e_card).decode()
			card_card = self.recreate_card(card_str)
			#print(card_card)
			### END DECRYPT ###
			self.addCard(card_card)

		self.encrypted_hand = Encrypted_Hand(self.n)

	def add_encrypted_card(self, card):
		self.encrypted_hand.add_encrypted_card(card)

	def remove_encrypted_card(self, card):
		self.encrypted_hand.remove_encrypted_card(card)

	def recreate_card(self, card_str):
		ranks = {'2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, '10': 10, 'J': 11, 'Q': 12, 'K': 13, 'A': 14}
		suits = {'c': CLUBS, 'd': DIAMONDS, 's': SPADES, 'h': HEARTS}
		return Card(Rank13(ranks[card_str[:-1]]), Suit(suits[card_str[-1]]))

	def addCard(self, card):
		self.hand.addCard(card)

	def getInput(self, option):
		card = None
		while card is None:
			msg = "{}, select a card to {}: ".format(self.name, option)
			card = input(msg)
		return card

	def play(self, suit=None, option='play', c=None, auto=False):
		
		if c is not None:
			card = c

		elif self.autoplay or auto:

			if suit is None:
				return self.hand.getRandomCard()
			return self.hand.getRandomCard(suit)

		else:
			card = self.getInput(option)

		return self.hand.playCard(card) 

	def trickWon(self, trick):
		self.tricksWon.append(trick.trick)
		self.score += trick.points

	def hasSuit(self, suit):
		return len(self.hand.value[suit.iden]) > 0

	def removeCard(self, card):
		self.hand.removeCard(card)

	def discardTricks(self):
		self.tricksWon = []

	def hasOnlyHearts(self):
		return self.hand.hasOnlyHearts()

	def generate_asymmetric_keys(self):
		return self.crypto.key_pair_gen(4096)

	def generate_fernet_key(self):
		return self.crypto.generate_fernet_key()

	def perform_bit_commitment(self):
		return self.crypto.calculate_bit_commitment(self.hand)

	def save_bit_commitment(self, player_name, bit_commitment):
		self.crypto.other_bit_commitments[player_name] = bit_commitment

	def verify_bit_commitment_signature(self, bit_commitment):
		return self.crypto.verify_bit_commitment_signature(bit_commitment)
	
	def save_commitment_reveal(self, player_name, commitment_reveal):
		self.crypto.other_commitments_reveal[player_name] = commitment_reveal

	def verify_commitment(self, bit_commitment, commitment_reveal):
		return self.crypto.verify_commitment_reveal(bit_commitment, commitment_reveal)

	def encrypt_card(self, card):
		return self.crypto.encrypt_card(card)

	def decrypt_card(self, card):
		return self.crypto.decrypt_card(card)