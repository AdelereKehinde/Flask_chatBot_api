from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import smtplib
from email.mime.text import MIMEText
import random
import json
import requests
from datetime import datetime, timedelta, UTC
import os
from dotenv import load_dotenv
from flask_api.src.database import init_db, db
from flask_api.src.model import User, Chat

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///luminous_ai.db')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-here')
app.config['SMTP_EMAIL'] = 'adelerekehinde01@gmail.com'
app.config['SMTP_PASSWORD'] = 'wiyzipxahtgqlypb'

CORS(app, resources={r"/api/*": {"origins": "*", "methods": ["GET", "POST", "OPTIONS"], "allow_headers": ["Content-Type", "Authorization"]}})

bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# === FIX 1 & 2: JWT Identity Loaders ===
@jwt.user_identity_loader
def user_identity_lookup(user):
    return str(user)  # Ensure identity is always a string

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=int(identity)).first()  # Convert back to int for query

# === FIX 3: Token Expiration ===
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)

# Initialize database
init_db(app)

# Create tables within application context
with app.app_context():
    db.create_all()
    print("Database tables created successfully!")

# Middleware for logging
@app.before_request
def log_request():
    if request.endpoint not in ['static']:
        print(f"\n--- Request Start ---")
        print(f"{request.method} {request.path}")
        auth_header = request.headers.get('Authorization')
        if auth_header:
            print(f"Authorization header: {auth_header[:20]}...")
        else:
            print("No Authorization header provided")
        content_type = request.headers.get('Content-Type', 'None')
        print(f"Content-Type: {content_type}")
        if request.method in ['POST', 'PUT']:
            raw_body = request.get_data(as_text=True)
            print(f"Raw body: {raw_body[:100]}{'...' if len(raw_body) > 100 else ''}")
        print(f"--- Request End ---")

# OpenRouter API configuration
OPENROUTER_API_KEY = "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"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def send_otp_email(email, otp):
    try:
        subject = "Luminous AI - OTP Verification"
        body = f"""
        <html>
            <body>
                <h2>Welcome to Luminous AI!</h2>
                <p>Your OTP verification code is: <strong>{otp}</strong></p>
                <p>This code will expire in 10 minutes.</p>
                <br>
                <p>Best regards,<br>Luminous AI Team</p>
            </body>
        </html>
        """
        
        msg = MIMEText(body, 'html')
        msg['Subject'] = subject
        msg['From'] = app.config['SMTP_EMAIL']
        msg['To'] = email
        
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
            server.login(app.config['SMTP_EMAIL'], app.config['SMTP_PASSWORD'])
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def generate_otp():
    return str(random.randint(100000, 999999))

# ---------------- LOGIN ----------------
@app.route('/api/login', methods=['POST'])
def login():
    try:
        print(f"\n--- Login Request ---")
        content_type = request.headers.get('Content-Type', 'None')
        print(f"Headers: Content-Type={content_type}")
        raw_body = request.get_data(as_text=True)
        print(f"Raw body: {raw_body[:100]}{'...' if len(raw_body) > 100 else ''}")
        
        data = request.get_json(silent=True)
        print(f"Parsed JSON: {data}")
        if not data:
            return jsonify({'error': 'Request body must be valid JSON. Ensure Content-Type is application/json and body is properly formatted.'}), 400

        email = data.get('email')
        password = data.get('password')
        print(f"Email: {email}, Password: {'*' * len(password) if password else None}")

        if not email or not password:
            return jsonify({'error': 'Email and password are required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"No user found for email: {email}")
            return jsonify({'error': 'Invalid credentials'}), 401
        if not bcrypt.check_password_hash(user.password, password):
            print(f"Password mismatch for email: {email}")
            return jsonify({'error': 'Invalid credentials'}), 401

        # === FIX 4: Convert to string in token creation ===
        access_token = create_access_token(identity=str(user.id))
        response_data = {
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'is_verified': user.is_verified
            }
        }
        if not user.is_verified:
            response_data['warning'] = 'Account not verified. Please verify your email to access all features.'
        print(f"Login successful for user ID: {user.id}")
        return jsonify(response_data), 200

    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/register', methods=['POST'])
def register():
    try:
        data = request.get_json(silent=True)
        print(f"Register body: {data}")
        if not data:
            return jsonify({'error': 'Request body must be valid JSON'}), 400

        email = data.get('email')
        password = data.get('password')
        name = data.get('name')
        
        if not email or not password or not name:
            return jsonify({'error': 'Email, password, and name are required'}), 400
        
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"Email already exists: {email}")
            return jsonify({'error': 'Email already exists'}), 400
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        otp = generate_otp()
        
        user = User(
            email=email,
            password=hashed_password,
            name=name,
            otp=otp,
            otp_expiry=datetime.now(UTC) + timedelta(minutes=10)
        )
        
        db.session.add(user)
        db.session.commit()
        print(f"User registered: {email}, OTP: {otp}")
        
        if send_otp_email(email, otp):
            return jsonify({'message': 'OTP sent to email'}), 201
        else:
            return jsonify({'error': 'Failed to send OTP'}), 500
            
    except Exception as e:
        print(f"Register error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json(silent=True)
        print(f"Verify OTP body: {data}")
        if not data:
            return jsonify({'error': 'Request body must be valid JSON'}), 400

        email = data.get('email')
        otp = data.get('otp')

        if not email or not otp:
            return jsonify({'error': 'Email and OTP are required'}), 400

        user = User.query.filter_by(email=email).first()
        if not user:
            print(f"No user found for email: {email}")
            return jsonify({'error': 'User not found'}), 404

        if user.is_verified:
            # === FIX 4: Convert to string in token creation ===
            access_token = create_access_token(identity=str(user.id))
            print(f"User already verified: {email}")
            return jsonify({
                'message': 'Account already verified',
                'access_token': access_token,
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'name': user.name,
                    'is_verified': user.is_verified
                }
            }), 200

        if user.otp != otp or datetime.now(UTC) > user.otp_expiry:
            print(f"Invalid or expired OTP for email: {email}")
            return jsonify({'error': 'Invalid or expired OTP'}), 400

        user.is_verified = True
        user.otp = None
        user.otp_expiry = None
        db.session.commit()
        print(f"OTP verified for email: {email}")

        # === FIX 4: Convert to string in token creation ===
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            'message': 'OTP verified successfully',
            'access_token': access_token,
            'user': {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'is_verified': user.is_verified
            }
        }), 200

    except Exception as e:
        print(f"Verify OTP error: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/chat/<int:chat_id>', methods=['GET'])
@jwt_required()
def get_chat(chat_id):
    try:
        # === FIX 4: Convert string back to int ===
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        user = User.query.get(user_id)
        if not user.is_verified:
            print(f"Unverified user attempted access: {user_id}")
            return jsonify({'error': 'Account not verified. Please verify your email.'}), 403

        chat = Chat.query.filter_by(id=chat_id, user_id=user_id).first()
        if not chat:
            print(f"Chat not found: ID {chat_id}, User {user_id}")
            return jsonify({'error': 'Chat not found'}), 404

        messages = json.loads(chat.messages) if chat.messages else []

        return jsonify({
            'chat': {
                'id': chat.id,
                'title': chat.title,
                'messages': messages,
                'created_at': chat.created_at.isoformat() if chat.created_at else None,
                'updated_at': chat.updated_at.isoformat() if chat.updated_at else None
            }
        }), 200

    except Exception as e:
        print(f"Get chat error: {str(e)}")
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500

@app.route('/api/chat', methods=['POST'])
@jwt_required()
def chat():
    try:
        # === FIX 4: Convert string back to int ===
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        user = User.query.get(user_id)
        if not user.is_verified:
            print(f"Unverified user attempted chat: {user_id}")
            return jsonify({'error': 'Account not verified. Please verify your email.'}), 403

        data = request.get_json(silent=True)
        print(f"Received data: {data}")
        if not data:
            return jsonify({"error": "Request body must be valid JSON"}), 400

        message = data.get('message')
        if not message:
            return jsonify({"error": "The 'message' field is required"}), 400
        if not isinstance(message, str):
            return jsonify({"error": "The 'message' field must be a string"}), 400
        if not message.strip():
            return jsonify({"error": "The 'message' field cannot be empty"}), 400

        chat_id = data.get('chat_id')
        if chat_id is not None and not isinstance(chat_id, int):
            return jsonify({"error": "The 'chat_id' field must be an integer if provided"}), 400

        print(f"User ID: {user_id}")
        headers = {
            'Authorization': f'Bearer {OPENROUTER_API_KEY}',
            'Content-Type': 'application/json'
        }
        payload = {
            'model': 'deepseek/deepseek-chat',
            'messages': [{'role': 'user', 'content': message}]
        }

        response = requests.post(OPENROUTER_URL, json=payload, headers=headers)
        print(f"OpenRouter response status: {response.status_code}, content: {response.text}")
        if response.status_code != 200:
            return jsonify({'error': 'AI service unavailable'}), 500

        response_data = response.json()
        if 'choices' not in response_data or not response_data['choices']:
            return jsonify({'error': 'Invalid response from AI service'}), 500
        ai_response = response_data['choices'][0]['message']['content']

        if chat_id:
            chat = Chat.query.filter_by(id=chat_id, user_id=user_id).first()
            if chat:
                messages = json.loads(chat.messages) if chat.messages else []
                messages.extend([
                    {'role': 'user', 'content': message},
                    {'role': 'assistant', 'content': ai_response}
                ])
                chat.messages = json.dumps(messages)
                chat.updated_at = datetime.now(UTC)
            else:
                return jsonify({"error": "Chat not found"}), 404
        else:
            messages = [
                {'role': 'user', 'content': message},
                {'role': 'assistant', 'content': ai_response}
            ]
            chat = Chat(
                user_id=user_id,
                title=message[:50] + '...' if len(message) > 50 else message,
                messages=json.dumps(messages),
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC)
            )
            db.session.add(chat)

        db.session.commit()

        return jsonify({
            'response': ai_response,
            'chat_id': chat.id
        }), 200

    except Exception as e:
        print(f"Chat error: {str(e)}")
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500

@app.route('/api/chats', methods=['GET'])
@jwt_required()
def get_chats():
    try:
        # === FIX 4: Convert string back to int ===
        user_id_str = get_jwt_identity()
        user_id = int(user_id_str)
        
        user = User.query.get(user_id)
        if not user.is_verified:
            print(f"Unverified user attempted access: {user_id}")
            return jsonify({'error': 'Account not verified. Please verify your email.'}), 403

        chats = Chat.query.filter_by(user_id=user_id).order_by(Chat.updated_at.desc()).all()

        chats_data = []
        for chat in chats:
            chats_data.append({
                'id': chat.id,
                'title': chat.title,
                'updated_at': chat.updated_at.isoformat() if chat.updated_at else None,
                'created_at': chat.created_at.isoformat() if chat.created_at else None
            })

        return jsonify({'chats': chats_data}), 200

    except Exception as e:
        print(f"Get chats error: {str(e)}")
        return jsonify({'error': f"Unexpected error: {str(e)}"}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy', 'message': 'Luminous AI API is running'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)