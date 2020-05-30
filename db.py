import sqlite3
#from card_game import * (have to change this in game_mode)
from user import User

class Sqlite():


	def  __init__(self):
		self.conn = sqlite3.connect(':memory:')
		self.conn.row_factory = self.dict_factory
		self.c = self.conn.cursor()
		self.c.execute("""CREATE TABLE tblGame (
			'ID'	INTEGER NOT NULL PRIMARY KEY  UNIQUE
		);""")

		self.c.execute("""CREATE TABLE tblGameType (
			'GameTypeID'	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
			'GameName'	TEXT
		); """)
		self.c.execute(""" CREATE TABLE User (
			'NIF' INTEGER NOT NULL PRIMARY KEY  UNIQUE,
			'RANK' INTEGER NOT NULL);
			""")

		self.c.execute("""CREATE TABLE tblScore (
			'ScoreID'	INTEGER NOT NULL PRIMARY KEY UNIQUE,
			'GameID'	INTEGER,
			'UserID'	INTEGER ,
			FOREIGN KEY (GameID) REFERENCES tblGame(ID),
			FOREIGN KEY (UserID) REFERENCES User(NIF)
			);""")

		self.c.execute(""" CREATE TABLE "Users_games" (
			"User_nif" integer PRIMARY KEY REFERENCES "User" ("NIF"),
			"Game_id" integer REFERENCES "tblGame" ("ID")
		);
		""")
		
		self.c.execute("INSERT INTO User VALUES (:nif, :rank)",{'nif' : 22,'rank':2})
		self.c.execute("INSERT INTO User VALUES (:nif, :rank)",{'nif' : 11,'rank':1})

	def insert_games(self,id):
		with self.conn:
				self.c.execute('INSERT INTO tblGame VALUES (:id);',{'id':id})

	def users_by_nif(self,NIF):
		with self.conn:
			self.c.execute('SELECT * FROM User WHERE NIF=NIF',{'NIF' : NIF})
			return self.c.fetchone()
			
	def insert_users(self,user):
		with self.conn:
			self.c.execute("INSERT INTO User VALUES (:nif, :rank)",{'nif' : User.nif,'rank':User.rank})

	def users_by_nif(self,NIF):
		with conn:
			self.c.execute('SELECT * FROM User WHERE NIF=NIF',{'NIF' : NIF})
			return self.c.fetchone

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
