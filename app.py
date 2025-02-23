from flask import Flask, url_for, redirect, request, jsonify, session
from flask_socketio import SocketIO, join_room, emit
from pymongo import MongoClient
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
from dotenv import load_dotenv
import os, random, string, sys, datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
oauth = OAuth(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket

app.secret_key = os.getenv('RANDOM_KEY')

try:
    client = MongoClient(os.getenv('MONGO_URI'))
except:
    print("Invalid MongoDB URI. Check your Atlas connection string.")
    sys.exit(1)

# Database
db = client.get_database('mydatabase')
users = db.users
teamdb = db.teamdb
chat = db.messages

CORS(app)

google = oauth.register(
    name='google',
    client_id=os.getenv('CLIENT_ID'),
    client_secret=os.getenv('CLIENT_SECRET'),
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    access_token_url='https://oauth2.googleapis.com/token',
    api_base_url='https://www.googleapis.com/oauth2/v3/',
    client_kwargs={'scope': 'openid profile email'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)

def generate_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@app.route('/')
def home():
    if not session.get('auth'):
        return "home"
    return redirect('/TeamRegistration')

@app.route('/google')
def google_login():
    redirect_uri = url_for("authorize_google", _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route("/authorize/google")
def authorize_google():
    token = google.authorize_access_token()
    resp = google.get("userinfo")
    user_info = resp.json()
    email = user_info.get("email")

    if not users.find_one({"email": email}):
        users.insert_one({
            "username": user_info.get("given_name"),
            "email": email,
        })

    session['auth'] = True
    session['email'] = email
    session['username'] = user_info.get("given_name")
    return redirect('/TeamRegistration')

@app.route('/TeamRegistration', methods=['POST'])
def team_registration():
    if not session.get('auth'):
        return jsonify({"error": "Unauthorized"}), 401  # Return JSON instead of redirect

    data = request.json
    team_name = data.get('teamName')
    slogan = data.get("teamSlogan")
    bio = data.get("shortBio")

    # Check if team name already exists
    if teamdb.find_one({'team_name': team_name}):
        return jsonify({"error": "Team name already exists"}), 400

    # Generate a unique team code
    teamcode = generate_code()

    # Insert team details into the database
    teamdb.insert_one({
        "Admin": "haiii",#session['email'],
        "username": "Raakesh,"#session['username'],
        "team_name": team_name,
        "teamcode": teamcode,
        "teamSlogan": slogan,
        "teamBio": bio,
    })

    return jsonify({"message": "Team registered successfully!", "team_name": team_name}), 201

@app.route('/joinTeam', methods=['POST'])
def join_team():
    if not session.get('auth'):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    teamcode = data.get('teamcode')

    existing_team = teamdb.find_one({'teamcode': teamcode})

    if existing_team:
        return jsonify({"message": "Joined team successfully!", "team_name": existing_team['team_name']}), 200
    else:
        return jsonify({"error": "No teams found"}), 404

@app.route('/community/<team_name>')
def room(team_name):
    if not session.get('auth'):
        return redirect('/')

    room_data = teamdb.find_one({"team_name": team_name})

    if not room_data:
        return redirect('/TeamRegistration')

    teamcode = room_data['teamcode']
    room_messages = list(chat.find({"teamcode": teamcode}).sort("timestamp", 1))

    return jsonify({
        "teamcode": teamcode,
        "team_name": team_name,
        "messages": room_messages
    })

@socketio.on('join')
def handle_join(data):
    room = data['room']
    join_room(room)

@socketio.on('send_message')
def handle_message(data):
    room = data['room']
    message = data['message']
    email = session.get('email')

    if not email:
        return
    user_data = users.find_one({"email": email})
    if not user_data:
        return

    username = user_data.get("username")
    team_data = teamdb.find_one({"teamcode": room})
    if not team_data:
        return

    team_name = team_data.get("team_name")

    message_data = {
        "teamcode": room,
        "team_name": team_name,
        "username": username,
        "message": message,
        "timestamp": datetime.datetime.utcnow()
    }
    chat.insert_one(message_data)

    emit('receive_message', {'username': username, 'message': message}, room=room)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5050)
