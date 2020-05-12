from flask import Flask, render_template,request,jsonify
from flask_socketio import SocketIO,send,emit,join_room,leave_room
from flask_cors import CORS, cross_origin
from flask_jwt import JWT, jwt_required, current_identity
from cards_main import Hearts
from card_game import Player
from utils import Crypto
from user import User
import json
from random import randint,choice
import string

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'super-secret'
cors = CORS(app,resources={r"/auth": {"origins": "*"},r"/token":{"origins": "*"}})
socketio = SocketIO(app,cors_allowed_origins="*")

crypto = Crypto(None,None,None)

rooms={"1":Hearts(),"2": Hearts()}

leaderboard={"1111111":1, "12345678":2,"87654321":3,"23145546":4}

users={"252811518": User("252811518",2,None)}

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
        emit('join-room',{'id':message, 'status':'full'})
    else:
        # Join socket IO room to facilitate broadcasting messages
        join_room(message)
        # Join our server room
        # TODO better random player name
        pname = "Player "+str(randint(1,100))
        rooms[message].players.append(Player(request.sid,pname))

        emit('join-room',{'id':message, 'status':'success'})

@socketio.on('leave-room')
def leaveRoom(message):
    try:
        # TODO rework
        for pl in rooms[message].players:
            if pl.id == request.sid:
                rooms[message].players.remove(pl)
    except:
        pass
    leave_room(message)

@socketio.on('hearts-message')
def msg(message):
    # TODO Validate room
    room = message['room']
    player = [pl for pl in rooms[room].players if pl.id == request.sid][0]
    data = message['data']
    #Simulate a game start after receiving a message
    game = rooms[room] 

    # Echo message
    emit('hearts-message',{'player':player.name,'data':data},room = room)

if __name__ == '__main__':
    socketio.run(app)