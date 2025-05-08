from flask import Blueprint, request, jsonify
from googletrans import Translator

translate_bp = Blueprint('translate', __name__)
translator = Translator()

@translate_bp.route('/translate', methods=['POST'])
def translate():
    data = request.json
    text = data.get('text')
    target_language = data.get('language', 'en')  # Default to English
    translated = translator.translate(text, dest=target_language)
    return jsonify({'translated_text': translated.text})
