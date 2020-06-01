from xp_handling import get_level

class User:

	def __init__(self,nif,token,rank=1,xp=0):
		self.nif = nif
		self.token = token
		self.xp = xp
		self.rank = get_level(self.xp)
