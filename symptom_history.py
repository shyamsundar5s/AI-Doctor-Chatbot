from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from datetime import datetime

history = Blueprint('history', __name__)

# Symptom History model
class SymptomHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    symptoms = db.Column(db.Text, nullable=False)
    advice = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

@history.route('/save_history', methods=['POST'])
@jwt_required()
def save_history():
    user_id = get_jwt_identity()
    data = request.json
    new_entry = SymptomHistory(user_id=user_id, symptoms=data['symptoms'], advice=data['advice'])
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({'message': 'Symptom history saved successfully'})

@history.route('/get_history', methods=['GET'])
@jwt_required()
def get_history():
    user_id = get_jwt_identity()
    history = SymptomHistory.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'symptoms': h.symptoms,
        'advice': h.advice,
        'timestamp': h.timestamp
    } for h in history])
