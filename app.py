from flask import Flask, jsonify, request, make_response
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from email_validator import validate_email, EmailNotValidError
import os
import jwt
from datetime import datetime, timedelta
import bcrypt
import re
import uuid
from functools import wraps
from utils.logger import logger
from utils.middleware import request_middleware, log_function_call
from werkzeug.exceptions import BadRequest

def create_app():
    # Load environment variables
    load_dotenv()

    # Initialize Flask app
    app = Flask(__name__)

    # Set testing mode based on environment variable
    app.config['TESTING'] = os.getenv('TESTING', 'False').lower() == 'true'

    # Configure middleware
    request_middleware(app)

    # Configure CORS
    CORS(app, resources={
        r"/auth/*": {"origins": os.getenv('ALLOWED_ORIGINS', '*').split(','),
                    "methods": ["POST"],
                    "allow_headers": ["Content-Type", "Authorization"]},
        r"/": {"origins": "*"}  # Allow all origins for the root path
    })

    # Configure rate limiting based on testing mode
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"],
        storage_uri=os.getenv('RATELIMIT_STORAGE_URL', "memory://"),
        enabled=not app.config['TESTING']  # Disable rate limiting in test mode
    )

    # Password validation regex - making it slightly more lenient while maintaining security
    app.config['PASSWORD_PATTERN'] = r"^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$"

    # Mock user database - in a real application, this would be a database
    app.users_db = {}

    def validate_password(password):
        """Validate password complexity."""
        if not password or len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Za-z]", password):
            return False, "Password must contain at least one letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one number"
        if not re.search(r"[@$!%*#?&]", password):
            return False, "Password must contain at least one special character"
        return True, None

    def validate_input_length(email, password):
        """Validate input lengths."""
        if len(email) > 254:  # RFC 5321
            return False, "Email is too long"
        if len(password) > 72:  # bcrypt limitation
            return False, "Password is too long"
        return True, None

    def validate_login_input(email, password):
        """Validate login input fields."""
        if not email or not password:
            return False, "Missing email or password"

        try:
            # Validate email
            validation_kwargs = {
                'check_deliverability': False,  # Disable deliverability check for testing
            }
            validate_email(email, **validation_kwargs)
        except EmailNotValidError as e:
            return False, str(e)

        return True, None

    def validate_signup_input(email, password, confirm_password):
        """Validate signup input fields."""
        if not email or not password or not confirm_password:
            return False, "All fields are required"

        try:
            # Validate email
            validation_kwargs = {
                'check_deliverability': False,  # Disable deliverability check for testing
            }
            validation = validate_email(email, **validation_kwargs)
            email = validation.normalized

            # Check if email already exists (case-insensitive)
            if email.lower() in (e.lower() for e in app.users_db.keys()):
                return False, "Email already registered"

        except EmailNotValidError as e:
            return False, str(e)

        # Check password match
        if password != confirm_password:
            return False, "Passwords do not match"

        # Validate input lengths
        is_valid, msg = validate_input_length(email, password)
        if not is_valid:
            return False, msg

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
    @limiter.limit("10/minute", exempt_when=lambda: app.config['TESTING'])
    @log_function_call
    def health_check():
        logger.debug('Health check endpoint called')
        return jsonify({
            'status': 'healthy',
            'message': 'API is running'
        }), 200

    @app.route('/auth/signup', methods=['POST'])
    @limiter.limit("5 per minute", exempt_when=lambda: app.config['TESTING'])
    @log_function_call
    def signup():
        """User registration endpoint."""
        try:
            try:
                data = request.get_json()
                if not data:
                    return jsonify({'error': 'Missing required fields'}), 400
            except BadRequest as e:
                return jsonify({'error': 'Missing required fields'}), 400
            
            if not all(k in data for k in ['email', 'password', 'confirm_password']):
                return jsonify({'error': 'All fields are required'}), 400

            email = data['email'].lower().strip()
            password = data['password']
            confirm_password = data['confirm_password']

            # Validate input
            is_valid, error_message = validate_signup_input(email, password, confirm_password)
            if not is_valid:
                return jsonify({'error': error_message}), 400

            # Hash password and store user
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            user_id = str(uuid.uuid4())
            app.users_db[email] = {
                'password': hashed_password,
                'user_id': user_id,
                'created_at': datetime.now().isoformat(),
                'failed_attempts': 0,
                'last_failed_attempt': None
            }

            return jsonify({
                'message': 'User registered successfully'
            }), 201

        except Exception as e:
            logger.error('Signup failed', extra={'error': str(e)}, exc_info=True)
            return jsonify({'error': 'An unexpected error occurred'}), 500

    @app.route('/auth/login', methods=['POST'])
    @limiter.limit("5 per minute", exempt_when=lambda: app.config['TESTING'])  # Exempt from rate limiting in test mode
    @log_function_call
    def login():
        try:
            # Set request timeout
            request.environ['REQUEST_TIMEOUT'] = 30

            # Get and validate input
            try:
                data = request.get_json()
            except Exception as e:
                logger.warning('Invalid JSON payload', extra={'error': str(e)})
                return jsonify({'error': 'Invalid JSON payload'}), 400

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
            if email not in app.users_db:
                # Use constant time comparison to prevent timing attacks
                bcrypt.checkpw(password.encode('utf-8'), bcrypt.gensalt())  # Dummy check
                logger.warning('Login attempt for non-existent user', extra={'email': email})
                return jsonify({'error': 'Invalid email or password'}), 401

            user = app.users_db[email]

            # Check for account lockout
            if user.get('failed_attempts', 0) >= 5:
                last_attempt = user.get('last_failed_attempt')
                if last_attempt and (datetime.now() - last_attempt).total_seconds() < 900:  # 15 minutes
                    logger.warning('Login attempt for locked account', extra={'email': email})
                    return jsonify({'error': 'Account temporarily locked. Please try again later'}), 429

                # Reset failed attempts after lockout period
                user['failed_attempts'] = 0

            # Verify password
            if not bcrypt.checkpw(password.encode('utf-8'), user['password']):
                # Update failed attempts
                user['failed_attempts'] = user.get('failed_attempts', 0) + 1
                user['last_failed_attempt'] = datetime.now()
                logger.warning('Failed login attempt', extra={
                    'email': email,
                    'failed_attempts': user['failed_attempts']
                })
                return jsonify({'error': 'Invalid email or password'}), 401

            # Generate JWT token
            token = jwt.encode(
                {
                    'user_id': user['user_id'],
                    'email': email,
                    'exp': datetime.utcnow() + timedelta(hours=1),
                    'iat': datetime.utcnow(),
                    'jti': os.urandom(16).hex()
                },
                os.getenv('SECRET_KEY'),
                algorithm='HS256'
            )

            return jsonify({
                'token': token,
                'user': {
                    'email': email,
                    'user_id': user['user_id']
                }
            }), 200

        except Exception as e:
            logger.error('Login failed', extra={'error': str(e)}, exc_info=True)
            return jsonify({'error': 'An unexpected error occurred'}), 500

    @app.route('/')
    def root():
        """Root endpoint that provides API information."""
        return jsonify({
            'name': 'Auth Template API',
            'version': '1.0',
            'endpoints': {
                'health': '/health',
                'signup': '/auth/signup',
                'login': '/auth/login'
            },
            'documentation': 'See README.md for API documentation'
        }), 200

    return app

# Create the app instance for running directly
app = create_app()

if __name__ == '__main__':
    logger.info('Starting application', extra={
        'environment': os.getenv('FLASK_ENV', 'development'),
        'debug_mode': os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    })
    
    if os.getenv('FLASK_ENV') == 'production':
        app.config['SESSION_COOKIE_SECURE'] = True
        app.config['SESSION_COOKIE_HTTPONLY'] = True
        app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
    app.run(debug=os.getenv('DEBUG', 'False').lower() == 'true') 