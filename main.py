from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager
from auth import auth
from symptom_history import history
from admin import admin_bp
from multilingual import translate_bp
from chatbot import chatbot

# Initialize Flask app
app = Flask(__name__)

# Configurations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///doctor_chatbot.db'
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'

# Initialize Extensions
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Register Blueprints
app.register_blueprint(auth, url_prefix='/auth')
app.register_blueprint(history, url_prefix='/history')
app.register_blueprint(admin_bp, url_prefix='/admin')
app.register_blueprint(translate_bp, url_prefix='/translate')
app.register_blueprint(chatbot, url_prefix='/chat')

@app.before_first_request
def create_tables():
    """
    Create all necessary database tables before the first request.
    """
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
