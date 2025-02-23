from flask import Flask, url_for, redirect, request, jsonify, session
from flask_socketio import SocketIO, join_room, emit
from flask_sqlalchemy import SQLAlchemy
from authlib.integrations.flask_client import OAuth
from flask_cors import CORS
from dotenv import load_dotenv
import os, random, string, sys, datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
oauth = OAuth(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # Allow CORS for WebSocket
CORS(app)

app.secret_key = os.getenv('RANDOM_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_email = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    team_name = db.Column(db.String(120), unique=True, nullable=False)
    teamcode = db.Column(db.String(6), unique=True, nullable=False)
    teamSlogan = db.Column(db.String(255))
    teamBio = db.Column(db.Text)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    teamcode = db.Column(db.String(6), nullable=False)
    team_name = db.Column(db.String(120), nullable=False)
    username = db.Column(db.String(80), nullable=False)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)

db.create_all()

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

    if not User.query.filter_by(email=email).first():
        new_user = User(username=user_info.get("given_name"), email=email)
        db.session.add(new_user)
        db.session.commit()

    session['auth'] = True
    session['email'] = email
    session['username'] = user_info.get("given_name")
    return redirect('/TeamRegistration')

@app.route('/TeamRegistration', methods=['POST'])
def team_registration():
    data = request.json
    team_name = data.get('teamName')
    slogan = data.get("slogan")
    bio = data.get("bio")

    if Team.query.filter_by(team_name=team_name).first():
        return jsonify({"error": "Team name already exists"}), 400

    teamcode = generate_code()
    new_team = Team(admin_email=session['email'], username=session['username'], team_name=team_name, teamcode=teamcode, teamSlogan=slogan, teamBio=bio)
    db.session.add(new_team)
    db.session.commit()

    return jsonify({"message": "Team registered successfully!", "team_name": team_name}), 201

@app.route('/joinTeam', methods=['POST'])
def join_team():
    if not session.get('auth'):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.json
    teamcode = data.get('teamcode')
    existing_team = Team.query.filter_by(teamcode=teamcode).first()

    if existing_team:
        return jsonify({"message": "Joined team successfully!", "team_name": existing_team.team_name}), 200
    else:
        return jsonify({"error": "No teams found"}), 404

@app.route('/community/<team_name>')
def room(team_name):
    if not session.get('auth'):
        return redirect('/')

    room_data = Team.query.filter_by(team_name=team_name).first()

    if not room_data:
        return redirect('/TeamRegistration')

    teamcode = room_data.teamcode
    room_messages = Message.query.filter_by(teamcode=teamcode).order_by(Message.timestamp.asc()).all()
    messages = [{"username": m.username, "message": m.message, "timestamp": m.timestamp} for m in room_messages]

    return jsonify({
        "teamcode": teamcode,
        "team_name": team_name,
        "messages": messages
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
    user = User.query.filter_by(email=email).first()
    if not user:
        return

    team = Team.query.filter_by(teamcode=room).first()
    if not team:
        return

    new_message = Message(teamcode=room, team_name=team.team_name, username=user.username, message=message)
    db.session.add(new_message)
    db.session.commit()

    emit('receive_message', {'username': user.username, 'message': message}, room=room)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == "__main__":
    socketio.run(app, debug=True, port=5050)
