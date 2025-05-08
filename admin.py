from flask import Blueprint, jsonify
from flask_jwt_extended import jwt_required
from functools import wraps

admin_bp = Blueprint('admin', __name__)

# Admin model or decorator
def admin_required(func):
    @wraps(func)
    @jwt_required()
    def wrapper(*args, **kwargs):
        # Check if the user is an admin (logic to check admin here)
        user_id = get_jwt_identity()
        # Assume we have an is_admin field in the user model
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({'error': 'Admin access required'}), 403
        return func(*args, **kwargs)
    return wrapper

@admin_bp.route('/user_statistics', methods=['GET'])
@admin_required
def user_statistics():
    users = User.query.count()
    histories = SymptomHistory.query.count()
    return jsonify({'total_users': users, 'total_histories': histories})
