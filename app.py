from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import openai
from googletrans import Translator

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doctor_chatbot.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'
openai.api_key = "your-openai-api-key"

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)
translator = Translator()

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

class SymptomHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    symptoms = db.Column(db.Text, nullable=False)
    advice = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Routes
@app.route('/')
def index():
    return render_template('index.html')

# User Authentication
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.json
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/auth/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data['username']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify({'token': access_token})
    return jsonify({'error': 'Invalid credentials'}), 401

# Chatbot Functionality
@app.route('/chat', methods=['POST'])
@jwt_required()
def chat():
    user_id = get_jwt_identity()
    data = request.json
    user_input = data.get('message')
    target_language = data.get('language', 'en')  # Default to English

    if not user_input:
        return jsonify({'error': 'Empty input'}), 400

    try:
        # Translate input to English (if needed)
        translated_input = translator.translate(user_input, dest='en').text

        # Use OpenAI LLM to generate a response
        response = openai.ChatCompletion.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": "You are an AI doctor chatbot. Ask about symptoms and provide health advice."},
                {"role": "user", "content": translated_input}
            ]
        )
        advice = response['choices'][0]['message']['content']

        # Translate response back to the target language
        translated_advice = translator.translate(advice, dest=target_language).text

        # Save symptom history
        new_entry = SymptomHistory(user_id=user_id, symptoms=user_input, advice=advice)
        db.session.add(new_entry)
        db.session.commit()

        return jsonify({'response': translated_advice})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Symptom History
@app.route('/history', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    history = SymptomHistory.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'symptoms': h.symptoms,
        'advice': h.advice,
        'timestamp': h.timestamp
    } for h in history])

# Admin Dashboard
@app.route('/admin/statistics', methods=['GET'])
@jwt_required()
def user_statistics():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user or not user.is_admin:
        return jsonify({'error': 'Admin access required'}), 403

    users = User.query.count()
    histories = SymptomHistory.query.count()
    return jsonify({'total_users': users, 'total_histories': histories})

# Database Initialization
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
