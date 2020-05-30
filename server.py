from flask import Flask, render_template,request,jsonify
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

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'
cors = CORS(app,resources={r"/auth": {"origins": "*"},r"/token":{"origins": "*"},r"/user":{"origins": "*"}})
socketio = SocketIO(app,cors_allowed_origins="*")

crypto = Crypto()

rooms={"1":Hearts_Table(),"2": Hearts_Table()}

leaderboard={"1111111":1, "12345678":2,"87654321":3,"23145546":4}

users={"252811518": User("252811518",2,None), "224241540": User("224241540",1,None)}


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
		if jwt['nif'] in users:
			user = users.get(jwt['nif'])
			user.token = crypto.generate_token(jwt)
			return json.dumps(user.__dict__),200
		else:
			user = User(jwt['nif'],0,crypto.generate_token(jwt))
			return json.dumps(user.__dict__),500
	except:
		return 'Could not generate token',500
 

@app.route('/testtoken', methods=['GET'])
def ttoken():
	token = crypto.generate_token({'nif':'123456'})
	return jsonify({'token': token}),200

@app.route("/user", methods=['GET'])
@token_required
def getUser():
	payload = crypto.get_payload(request.headers['Authorization'])
	payload = json.loads(payload)
	if payload['nif'] and payload['nif'] in users:
		user = users.get(payload['nif'])
		user.token = request.headers['Authorization']
		return json.dumps(user.__dict__),200
	return "No user found",500

@socketio.on('connect')
def connect():
    print("Client connected")

@socketio.on('leaderboards')
def leaderboards(message):
	emit('leaderboards',leaderboard)

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
