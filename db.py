import sqlite3
from user import User

class Sqlite:


	def  __init__(self,path):
		self.conn = sqlite3.connect(path)
		self.conn.row_factory = self.dict_factory
		self.c = self.conn.cursor()

	def insert_games(self,id):
		with self.conn:
				self.c.execute('INSERT INTO tblGame VALUES (:id);',{'id':id})

	def user_by_nif(self,nif):
		with self.conn:
			cur = self.conn.cursor().execute("SELECT * FROM User WHERE NIF={wnif}".format(wnif=nif))
			res = cur.fetchone()
			return User(res['nif'],res['rank'],res['token']) if res else None
			
	def insert_user(self,user):
		with self.conn:
			self.c.execute("INSERT INTO User VALUES (:nif, :rank, :token)",{'nif' : user.nif,'rank':user.rank,'token':user.token})

	def update_token(self,nif,token):
		with self.conn:
			self.conn.cursor().execute("UPDATE User SET TOKEN='{token}' WHERE NIF={wnif}".format(wnif=nif,token=token))

	def users(self):
		self.c.execute("SELECT * FROM User")
		return self.c.fetchall()

	def update_xp(self,xp, NIF):
		with conn:
			c.execute("""UPDATE User SET XP = :xp WHERE NIF = :nif """,{'xp':User.xp,'nif':User.nif} )

	def check_game(self,id):
		with self.conn:
			self.c.execute("SELECT * FROM  tblGame WHERE ID = :id ",{'id':id})

	def leaderboards(self):
		with self.conn:
			res = self.c.execute('SELECT NIF, RANK FROM User ORDER BY RANK desc')
			return res.fetchall()
	
	def dict_factory(self,cursor, row):
		d = {}
		for idx, col in enumerate(cursor.description):
			d[col[0].lower()] = row[idx]
		return d	
