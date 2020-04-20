from flask import Flask, render_template,request,jsonify
from flask_socketio import SocketIO,send,emit,join_room,leave_room
from cards_main import Hearts
from card_game import Player
import json
from random import randint,choice
import string

app = Flask(__name__)
socketio = SocketIO(app,cors_allowed_origins="*")

rooms={"1":Hearts(),"2": None}

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

@app.route('/highscores')
def highscores():
	return render_template("highscore_proto.html");

@socketio.on('connect')
def connect():
    print("Client connected")

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
   
    game.newRound()

    print(player.hand)

    # Echo message
    emit('hearts-message',{'player':player.name,'data':data},room = room)

if __name__ == '__main__':
    socketio.run(app)