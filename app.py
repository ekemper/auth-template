from flask import Flask, jsonify, request, make_response
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from email_validator import validate_email, EmailNotValidError
import os
import jwt
import datetime
import bcrypt
import re
import uuid
from functools import wraps
from utils.logger import logger
from utils.middleware import request_middleware, log_function_call

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)

# Configure middleware
request_middleware(app)

# Configure CORS
CORS(app, resources={
    r"/auth/*": {"origins": os.getenv('ALLOWED_ORIGINS', '*').split(','),
                 "methods": ["POST"],
                 "allow_headers": ["Content-Type", "Authorization"]}
})

# Configure rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Password validation regex
PASSWORD_PATTERN = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"

# Mock user database - in a real application, this would be a database
users_db = {
    "example@email.com": {
        "password": bcrypt.hashpw("password123!".encode('utf-8'), bcrypt.gensalt()),
        "user_id": "1",
        "failed_attempts": 0,
        "last_failed_attempt": None
    }
}

def validate_password(password):
    """Validate password complexity."""
    if not re.match(PASSWORD_PATTERN, password):
        return False, "Password must be at least 8 characters long and contain at least one letter, one number, and one special character"
    return True, None

def validate_login_input(email, password):
    """Validate login input fields."""
    try:
        # Validate email
        validate_email(email)
    except EmailNotValidError as e:
        return False, str(e)

    # Validate password complexity
    is_valid, msg = validate_password(password)
    if not is_valid:
        return False, msg

    return True, None

def validate_signup_input(email, password, confirm_password):
    """Validate signup input fields."""
    try:
        # Validate email
        validation = validate_email(email, check_deliverability=True)
        email = validation.normalized

        # Check if email already exists
        if email in users_db:
            return False, "Email already registered"

    except EmailNotValidError as e:
        return False, str(e)

    # Check password match
    if password != confirm_password:
        return False, "Passwords do not match"

    # Validate password complexity
    is_valid, msg = validate_password(password)
    if not is_valid:
        return False, msg

    return True, None

def add_security_headers(response):
    """Add security headers to response."""
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

@app.after_request
def after_request(response):
    """Add security headers to all responses."""
    return add_security_headers(response)

@app.route('/health', methods=['GET'])
@limiter.limit("10/minute")
@log_function_call
def health_check():
    logger.debug('Health check endpoint called')
    return jsonify({
        'status': 'healthy',
        'message': 'API is running'
    }), 200

@app.route('/auth/signup', methods=['POST'])
@limiter.limit("3 per minute, 20 per hour")  # Strict rate limiting for signup
@log_function_call
def signup():
    try:
        # Set request timeout
        request.environ['REQUEST_TIMEOUT'] = 30

        # Get and validate input
        data = request.get_json()
        if not data:
            logger.warning('Signup attempt with no data provided')
            return jsonify({'error': 'No data provided'}), 400

        email = data.get('email', '').lower().strip()
        password = data.get('password', '')
        confirm_password = data.get('confirm_password', '')

        if not all([email, password, confirm_password]):
            logger.warning('Signup attempt with missing required fields')
            return jsonify({'error': 'All fields are required'}), 400

        # Validate input format
        is_valid, error_msg = validate_signup_input(email, password, confirm_password)
        if not is_valid:
            logger.warning('Signup attempt with invalid input', extra={'error': error_msg})
            return jsonify({'error': error_msg}), 400

        # Generate user ID
        user_id = str(uuid.uuid4())

        # Hash password with bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(rounds=12))

        # Store user in database
        users_db[email] = {
            "password": hashed_password,
            "user_id": user_id,
            "failed_attempts": 0,
            "last_failed_attempt": None,
            "created_at": datetime.datetime.utcnow().isoformat()
        }

        logger.info('User registered successfully', extra={
            'email': email,
            'user_id': user_id
        })

        # Generate JWT token
        token = jwt.encode(
            {
                'user_id': user_id,
                'email': email,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),
                'iat': datetime.datetime.utcnow(),
                'jti': os.urandom(16).hex()
            },
            os.getenv('SECRET_KEY'),
            algorithm='HS256'
        )

        response = jsonify({
            'message': 'User registered successfully',
            'token': token,
            'user': {
                'email': email,
                'user_id': user_id
            }
        })

        # Set secure cookie with token
        if os.getenv('FLASK_ENV') == 'production':
            response.set_cookie(
                'auth_token',
                token,
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=3600  # 1 hour
            )

        return response, 201

    except Exception as e:
        logger.error('Unexpected error during signup', extra={'error': str(e)}, exc_info=True)
        return jsonify({'error': 'An unexpected error occurred'}), 500

@app.route('/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Strict rate limiting for login attempts
@log_function_call
def login():
    try:
        # Set request timeout
        request.environ['REQUEST_TIMEOUT'] = 30

        # Get and validate input
        data = request.get_json()
        if not data:
            logger.warning('Login attempt with no data provided')
            return jsonify({'error': 'No data provided'}), 400

        email = data.get('email', '').lower().strip()
        password = data.get('password', '')

        if not email or not password:
            logger.warning('Login attempt with missing email or password')
            return jsonify({'error': 'Missing email or password'}), 400

        # Validate input format
        is_valid, error_msg = validate_login_input(email, password)
        if not is_valid:
            logger.warning('Login attempt with invalid input format', extra={'error': error_msg})
            return jsonify({'error': error_msg}), 400

        # Check if user exists
        if email not in users_db:
            # Use constant time comparison to prevent timing attacks
            bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())  # Dummy check
            logger.warning('Login attempt for non-existent user', extra={'email': email})
            return jsonify({'error': 'Invalid email or password'}), 401

        user = users_db[email]

        # Check for account lockout
        if user.get('failed_attempts', 0) >= 5:
            last_attempt = user.get('last_failed_attempt')
            if last_attempt and (datetime.datetime.utcnow() - last_attempt).total_seconds() < 900:  # 15 minutes
                logger.warning('Login attempt for locked account', extra={'email': email})
                return jsonify({'error': 'Account temporarily locked. Please try again later'}), 429

            # Reset failed attempts after lockout period
            user['failed_attempts'] = 0

        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
            # Update failed attempts
            user['failed_attempts'] = user.get('failed_attempts', 0) + 1
            user['last_failed_attempt'] = datetime.datetime.utcnow()
            logger.warning('Failed login attempt', extra={
                'email': email,
                'failed_attempts': user['failed_attempts']
            })
            return jsonify({'error': 'Invalid email or password'}), 401

        # Reset failed attempts on successful login
        user['failed_attempts'] = 0
        user['last_failed_attempt'] = None

        # Generate JWT token with appropriate claims
        token = jwt.encode(
            {
                'user_id': user['user_id'],
                'email': email,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1),  # Short expiration time
                'iat': datetime.datetime.utcnow(),  # Issued at time
                'jti': os.urandom(16).hex()  # Unique token ID
            },
            os.getenv('SECRET_KEY'),
            algorithm='HS256'
        )

        logger.info('Successful login', extra={'email': email, 'user_id': user['user_id']})

        response = jsonify({
            'token': token,
            'user': {
                'email': email,
                'user_id': user['user_id']
            }
        })

        # Set secure cookie with token
        if os.getenv('FLASK_ENV') == 'production':
            response.set_cookie(
                'auth_token',
                token,
                httponly=True,
                secure=True,
                samesite='Strict',
                max_age=3600  # 1 hour
            )

        return response, 200

    except Exception as e:
        logger.error('Unexpected error during login', extra={'error': str(e)}, exc_info=True)
        return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    logger.info('Starting application', extra={
        'environment': os.getenv('FLASK_ENV', 'development'),
        'debug_mode': os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    })
    
    if os.getenv('FLASK_ENV') == 'production':
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.run(debug=os.getenv('FLASK_DEBUG', 'False').lower() == 'true') 