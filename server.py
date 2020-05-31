from flask import Flask, render_template,request,jsonify,g
from flask_socketio import SocketIO,send,emit,join_room,leave_room
from flask_cors import CORS, cross_origin
from flask_jwt import JWT, jwt_required, current_identity
from cards_main import Hearts
from table import Hearts_Table
from card_game import Player
from utils import Crypto
from user import User
import json
from random import randint,choice
import string
from functools import wraps
from db import Sqlite
import sqlite3

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'
cors = CORS(app,resources={r"/auth": {"origins": "*"},r"/token":{"origins": "*"},r"/user":{"origins": "*"}})
socketio = SocketIO(app,cors_allowed_origins="*")

crypto = Crypto()

rooms={"1":Hearts_Table(),"2": Hearts_Table()}

leaderboard={"1111111":1, "12345678":2,"87654321":3,"23145546":4}

def get_db():
	db = getattr(g, '_database', None)
	if db is None:
		db = g._database = Sqlite('database.db')
	return db

@app.teardown_appcontext
def close_connection(exception):
	db = getattr(g, '_database', None)
	if db is not None:
		db.conn.close()

def token_required(f):
	@wraps(f)
	def decorated(*args,**kwargs):
		try:
			token = request.headers['Authorization']
		except:
			return jsonify({'message': 'Token is missing'}),403

		if not crypto.validate_token(token):
				return jsonify({'message': 'Invalid token'}),403
		return f(*args,**kwargs)
	return decorated

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/rooms', methods=['GET'])
def room():
	return jsonify(list(rooms.keys()))

@app.route('/room', methods=['POST'])
def createRoom():
	# TODO add option to POST with game type
	randomId = ''.join([choice(string.ascii_letters 
			+ string.digits) for n in range(16)]) 
	rooms[randomId] = Hearts()
	return json.dumps({'success':True}), 201, {'ContentType':'application/json'}

@app.route('/token', methods=['POST'])
def decode_token():
	token_str = request.data.decode("utf-8")
	try:
		token = crypto.decode_cmd_token(token_str)
		jwt = json.loads(token.decode('utf-8'))
		user = get_db().user_by_nif(jwt['nif'])
		# User exists in DB - login
		if user:
			tkn = crypto.generate_token(jwt)
			get_db().update_token(user.nif,tkn)
			user.token = tkn
			return json.dumps(user.__dict__),200
		# User is missing - register
		else:
			user = User(jwt['nif'],1,0,crypto.generate_token(jwt))
			get_db().insert_user(user)
			return json.dumps(user.__dict__),500
	except:
		return 'Could not generate token',500
 
@app.route('/testtoken', methods=['GET'])
def ttoken():
	token = crypto.generate_token({'nif':'22'})
	return jsonify({'token': token}),200

@app.route("/user", methods=['GET'])
@token_required
def getUser():
	payload = crypto.get_payload(request.headers['Authorization'])
	payload = json.loads(payload)
	nif = payload.get('nif',None)
	user = get_db().user_by_nif(nif)
	if user:
		get_db().update_token(user.nif,request.headers['Authorization'])
		return json.dumps(user.__dict__),200
	return "No user found",500

@app.route("/leaderboards", methods=['GET'])
def leaderboards():
	all = get_db().leaderboards()
	return jsonify(all),200

@socketio.on('connect')
def connect():
	print("Client connected")

@socketio.on('join-room')
def joinRoom(message):
	tj = rooms.get(message)
	if tj == None:
		emit('join-room',{'id':message, 'status':'missing'})
	elif len(tj.players) >= 4:
		return
	else:
		# Join socket IO room to facilitate broadcasting messages
		join_room(message)
		# Join our server room
		join = rooms[message].join(request.sid)
		if join[0] == 'success':
			# status = status, names = player names , players = number fo players
			emit('join-room',{'id':message, 'status': join[0], 'players': join[1]})
			# broadcast player join
			emit('join-room',{'id':message, 'status': 'opponent', 'opid':request.sid},room=message,include_self=False)
		else:
			emit('join-room',{'id':message, 'status': join[0]})

@socketio.on('leave-room')
def leaveRoom(message):
	try:
		# TODO rework
		for pl in rooms[message].players:
			if pl == request.sid:
				rooms[message].players.remove(pl)
	except:
		pass
	leave_room(message)

@socketio.on('hearts-message')
def msg(message):
	print(request.sid," ",message)
	room = message['room']
	game = rooms[room]
	(tosend,broadcast) = game.on_frame(request.sid,message['data'])
	print("Server: ",tosend,"Broadcast: ",broadcast)
	if broadcast == 'broadcast':
		emit('hearts-message',tosend,room=room)
	elif broadcast == 'reply':
		emit('hearts-message',tosend)
	else:
		emit('hearts-message',tosend,room=broadcast) 


if __name__ == '__main__':
	socketio.run(app)
