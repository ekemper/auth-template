import pytest
import os
import bcrypt
from app import app as flask_app
from dotenv import load_dotenv

# Load test environment variables
load_dotenv('.env.test')

@pytest.fixture
def app():
    """Create application for the tests."""
    flask_app.config.update({
        'TESTING': True,
        'SERVER_NAME': 'localhost:5000',
        'RATELIMIT_ENABLED': False,  # Disable rate limiting for tests
    })
    return flask_app

@pytest.fixture
def client(app):
    """Create a test client."""
    return app.test_client()

@pytest.fixture
def test_user():
    """Create a test user credentials."""
    return {
        'email': 'test@example.com',
        'password': 'TestPass123!',
        'user_id': '999'
    }

@pytest.fixture
def registered_user(app, test_user):
    """Create a pre-registered user in the mock database."""
    with app.app_context():
        from app import users_db
        users_db[test_user['email']] = {
            'password': bcrypt.hashpw(test_user['password'].encode('utf-8'), bcrypt.gensalt()),
            'user_id': test_user['user_id'],
            'failed_attempts': 0,
            'last_failed_attempt': None
        }
        yield test_user
        # Cleanup
        users_db.pop(test_user['email'], None) 