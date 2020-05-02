from card_game import Deck, Card, Suit, Rank, Rank13, Rank10, Player, Trick
from utils import Crypto
import time


'''
Change auto to False if you would like to play the game manually.
This allows you to make all passes, and plays for all four players.
When auto is True, passing is disabled and the computer plays the
game by "guess and check", randomly trying moves until it finds a
valid one.
'''
auto = False

sueca_totalTricks = 10
sueca_score_1 = 61
sueca_score_2 = 91
sueca_score_4 = 120

hearts_totalTricks = 13
hearts_maxScore = 10
QUEEN = 12
UNDEFINED = -1
CLUBS = 0
DIAMONDS = 1
SPADES = 2
HEARTS = 3
cardsToPass = 3

class Hearts:
	def __init__(self,players=[]):
		
		self.roundNum = 0
		self.trickNum = 0 # initialization value such that first round is round 0
		self.dealer = -1 # so that first dealer is 0
		self.passes = [1, -1, 2, 0] # left, right, across, no pass
		self.currentTrick = Trick()
		self.trickWinner = UNDEFINED
		self.heartsBroken = False
		self.losingPlayer = None
		self.passingCards = [[], [], [], []]
		self.crypto = Crypto("table")


		# Make four players

		#self.players = [Player("A", auto=True), Player("B", auto=True), Player("C", auto=True), Player("D", auto=True)]
		self.players = players

		'''
		Player physical locations:
		Game runs clockwise
			C
		B		D
			A
		'''

		# Generate a full deck of cards and shuffle it
		#self.newRound()

	def checkGotAll(self, got_em_all):
		for player in self.players:
			if got_em_all[0]:
				if player.name != got_em_all[1]:
					player.score = 26
				else:
					player.score = 0

	def handleScoring(self):
		p, highestScore = None, 0
		got_em_all = (False, None)
		for player in self.players:
			if player.score == 26:
				got_em_all = (True, player.name)

		self.checkGotAll(got_em_all)
		print("\nScores:\n")
		for player in self.players:
			player.total_score += player.score

			print("{}: {}".format(player.name, str(player.total_score)))
			player.score = 0
			if player.total_score > highestScore:
				p = player
				highestScore = player.total_score
			self.losingPlayer = p

		

	def newRound(self):
		self.deck = Deck()
		self.deck.shuffle()
		self.roundNum += 1
		self.trickNum = 0
		self.trickWinner = UNDEFINED
		self.heartsBroken = False
		#self.dealer = (self.dealer + 1) % len(self.players)
		self.dealer=1
		
		self.dealCards()

		self.currentTrick = Trick()
		self.passingCards = [[], [], [], []]
		for p in self.players:
			p.discardTricks()

	def getFirstTrickStarter(self):
		for i,p in enumerate(self.players):
			if p.hand.contains2ofclubs:
				self.trickWinner = i

	def dealCards(self):
		i = 0
		while(self.deck.size() > 0):
			self.players[i % len(self.players)].addCard(self.deck.deal_top())
			i += 1

	def evaluateTrick(self):
		self.trickWinner = self.currentTrick.winner
		p = self.players[self.trickWinner]
		p.trickWon(self.currentTrick)
		if self.trickNum < hearts_totalTricks-1:
			print(self.currentTrick.suit)
		print(p.name + " won the trick.")
		# print('Making new trick')
		self.currentTrick = Trick()
		print(self.currentTrick.suit)
		
	def passCards(self, index):
		print(self.printPassingCards())
		passTo = self.passes[self.trickNum] # how far to pass cards
		passTo = (index + passTo) % len(self.players) # the index to which cards are passed
		while len(self.passingCards[passTo]) < cardsToPass: # pass three cards
			passCard = None
			while passCard is None: # make sure string passed is valid
				passCard = self.players[index].play(option='pass')
				if passCard is not None:
					# remove card from player hand and add to passed cards
					self.passingCards[passTo].append(passCard)
					self.players[index].removeCard(passCard)

	def distributePassedCards(self):
		for i,passed in enumerate(self.passingCards):
			for card in passed:
				self.players[i].addCard(card)
		self.passingCards = [[], [], [], []]

	def playersMakeCommitments(self):
		for p in self.players:
			p.perform_bit_commitment()

	def saveBitCommitments(self):
		for p in self.players:
			self.crypto.players_bit_commitments[p.name] = p.crypto.bit_commitment
			print(p.crypto.bit_commitment)

	def distributeBitCommitments(self):
		players = [0, 1, 2, 3]
		for i in players:
			for j in players:
				if j != i:
					self.players[i].crypto.other_bit_commitments[self.players[j].name] = self.players[j].crypto.bit_commitment

	def saveCommitmentsReveal(self):
		for p in self.players:
			self.crypto.players_commitments_reveal[p.name] = p.crypto.commitment_reveal				

	def distributeCommitmentsReveal(self):
		players = [0, 1, 2, 3]
		for i in players:
			for j in players:
				if j != i:
					self.players[i].crypto.other_commitments_reveal[self.players[j].name] = self.players[j].crypto.commitment_reveal

	def verify_bit_commitments(self):
		for p in self.players:
			print("Commitment {1}match! -> {0}".format(p.name, "" if self.crypto.verify_commitment_reveal(self.crypto.players_bit_commitments[p.name], self.crypto.players_commitments_reveal[p.name]) else "mis"))

	def commitment_modules_start(self):
		self.playersMakeCommitments()
		self.saveBitCommitments()
		self.distributeBitCommitments()

	def commitment_modules_end(self):
		print() #spacing
		self.saveCommitmentsReveal()
		self.verify_bit_commitments()

	def printPassingCards(self):
		out = "[ "
		for passed in self.passingCards:
			out += "["
			for card in passed:
				out += card.__str__() + " "
			out += "] "
		out += " ]"
		return out

	def playersPassCards(self):
		
		self.printPlayers(passed=False)
		if (self.trickNum % 4) != 3: # don't pass every fourth hand
			for i in range(0, len(self.players)):
				print() # spacing
				self.printPlayer(i)
				self.passCards(i % len(self.players))

			self.distributePassedCards()
			self.printPlayers(passed=True)

	def playTrick(self, start):
		shift = 0
		if self.trickNum == 0:
			startPlayer = self.players[start]
			addCard = startPlayer.play(option="play", c='2c')

			startPlayer.removeCard(addCard)

			self.currentTrick.addCard(addCard, start)

			shift = 1 # alert game that first player has already played

		# have each player take their turn
		for i in range(start + shift, start + len(self.players)):
			self.printCurrentTrick()
			curPlayerIndex = i % len(self.players)
			self.printPlayer(curPlayerIndex)
			curPlayer = self.players[curPlayerIndex]
			addCard = None

			while addCard is None: # wait until a valid card is passed
				
				addCard = curPlayer.play(suit=self.currentTrick.suit.iden, auto=auto) # change auto to False to play manually


				# the rules for what cards can be played
				# card set to None if it is found to be invalid
				if addCard is not None:
					
					# if it is not the first trick and no cards have been played,
					# set the first card played as the trick suit if it is not a heart
					# or if hearts have been broken
					if self.trickNum != 0 and self.currentTrick.cardsInTrick == 0:
						if addCard.suit == Suit(HEARTS) and not self.heartsBroken:
							# if player only has hearts but hearts have not been broken,
							# player can play hearts
							if not curPlayer.hasOnlyHearts():
								print(curPlayer.hasOnlyHearts())
								print(curPlayer.hand.__str__())
								print("Hearts have not been broken.")
								addCard = None
							else:
								self.currentTrick.setTrickSuit(addCard)
						else:
							self.currentTrick.setTrickSuit(addCard)

					# player tries to play off suit but has trick suit
					#if addCard is not None and addCard.suit != self.currentTrick.suit:
					if addCard is not None:
						#if curPlayer.hasSuit(self.currentTrick.suit):
						#	print("Must play the suit of the current trick.")
						#	addCard = None
						#elif addCard.suit == Suit(hearts):
						if addCard.suit == Suit(HEARTS):
							self.heartsBroken = True

					if self.trickNum == 0:
						if addCard is not None:
							if addCard.suit == Suit(HEARTS):
								print("Hearts cannot be broken on the first hand.")
								self.heartsBroken = False
								addCard = None
							elif addCard.suit == Suit(SPADES) and addCard.rank == Rank(QUEEN):
								print("The queen of spades cannot be played on the first hand.")
								addCard = None

					if addCard is not None and self.currentTrick.suit == Suit(UNDEFINED):
						if addCard.suit == Suit(HEARTS) and not self.heartsBroken:
							print("Hearts not yet broken.")
							addCard = None

					

					if addCard is not None:
						if addCard == Card(Rank(QUEEN), Suit(SPADES)):
							self.heartsBroken = True
						curPlayer.removeCard(addCard)


			self.currentTrick.addCard(addCard, curPlayerIndex)
			
		self.evaluateTrick()
		self.trickNum += 1

	# print player's hand
	def printPlayer(self, i):
		p = self.players[i]
		print("{}'s hand: {}".format(p.name, str(p.hand)))

	# print all players' hands
	def printPlayers(self, passed=False):
		for p in self.players:
			print("{}: {}".format(p.name, str(p.hand)))

	# show cards played in current trick
	def printCurrentTrick(self):
		trickStr = '\nCurrent table:\n'
		trickStr += "Trick suit: " + self.currentTrick.suit.__str__() + "\n"
		for i, card in enumerate(self.currentTrick.trick):
			#print("Debug: {} {}".format(i, self.currentTrick.trick))
			if type(self.currentTrick.trick[i]) is Card:
				trickStr += self.players[i].name + ": " + str(card) + "\n"
			else:
				trickStr += self.players[i].name + ": None\n"
		print(trickStr)

	def getWinner(self):
		minScore = 200 # impossibly high
		winner = None
		for p in self.players:
			if p.total_score < minScore:
				winner = p
				minScore = p.total_score
		return winner

	def sleeper(self):
		time.sleep(5)



def main():
	hearts = Hearts([Player("ID1","A"), Player("ID2","B"), Player("ID3","C"), Player("ID4","D")])



if __name__ == '__main__':
	main()