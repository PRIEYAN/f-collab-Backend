from flask import Flask, url_for, redirect, request, render_template, session, jsonify
from flask_socketio import SocketIO, join_room, leave_room, send, emit
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
except pymongo.errors.ConfigurationError:
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
        return "home"  # Change this to render_template("index.html") when ready
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

@app.route('/TeamRegistration', methods=['POST', 'GET'])
def team_registration():
    data = request.json

    # Extracting form data
    #name = data.get('teamName')
    #slogan = data.get('teamSlogan')
    #user_name = data.get('userName')
    #bio = data.get('shortBio')

    if not session.get('auth'):
        return redirect('/')

    if request.method == 'POST':
        team_name = request.form.get('teamName')
        slogan = request.form.get("TeamSlogan")
        bio = request.form.get("ShortBio")

        # Check if team name already exists
        if teamdb.find_one({'team_name': team_name}):
            message = "Team name already exists"
            return render_template("TeamRegistration.html", message=message)

        # Generate a unique team code
        teamcode = generate_code()

        # Insert team details into the database
        teamdb.insert_one({
            "Admin": session['email'],
            "username": session['username'],
            "team_name": team_name,
            "teamcode": teamcode,
            "teamSlogan": slogan,
            "teamBio": bio,
        })

        return redirect(f'/community/{team_name}')  # Redirect to the chatroom

    return "Done"  # Change this to render_template('TeamRegistration.html') when ready

@app.route('/joinTeam',methods=['POST'])
def jointeam():
    if request.method=='POST':
        teamcode=request.form.get('teamcode')
    exisitingTeamcode=teamdb.find_one({'teamcode':teamcode})
    if exisitingTeamcode:
        return redirect('/community/<team_name>')
    message="*No teams found"
    return render_template('/joinTeam',message=message)

@app.route('/community/<team_name>')
def room(team_name):
    if not session.get('auth'):
        return redirect('/')

    # Fetch team data based on team_name
    room_data = teamdb.find_one({"team_name": team_name})
    
    if not room_data:
        return redirect('/TeamRegistration')

    teamcode = room_data['teamcode']  # Get teamcode
    room_messages = chat.find({"teamcode": teamcode}).sort("timestamp", 1)  # Fetch messages for the team

    return render_template('app.html', 
                           roomcode=teamcode, 
                           roomname=room_data, 
                           room_messages=room_messages, 
                           title=team_name 
                           )

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

    # Fetch the team details to get the team name
    team_data = teamdb.find_one({"teamcode": room})  
    if not team_data:
        return

    team_name = team_data.get("team_name") 

    # Insert message into the database
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