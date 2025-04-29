import os
import sys
import pytest
import json
import time
import jwt

# Add the parent directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, users_db, limiter

@pytest.fixture(autouse=True)
def disable_rate_limits():
    """Disable rate limiting for all tests."""
    limiter.enabled = False
    yield
    limiter.enabled = True

@pytest.fixture
def client():
    """Create a test client."""
    app.config['TESTING'] = True
    return app.test_client()

@pytest.fixture
def test_user():
    """Create a test user in the database."""
    user_data = {
        'email': 'test@example.com',
        'password': 'TestPass123!'
    }
    
    # Register the user first
    with app.test_client() as client:
        client.post('/auth/signup', 
            json={
                'email': user_data['email'],
                'password': user_data['password'],
                'confirm_password': user_data['password']
            },
            headers={'Content-Type': 'application/json'}
        )
    
    yield user_data
    
    # Cleanup
    users_db.pop(user_data['email'].lower(), None)

def test_login_success(client, test_user):
    """Test successful login with correct credentials."""
    response = client.post('/auth/login', 
        json={
            'email': test_user['email'],
            'password': test_user['password']
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'token' in data
    assert 'user' in data
    assert data['user']['email'] == test_user['email']

def test_login_wrong_password(client, test_user):
    """Test login with wrong password."""
    response = client.post('/auth/login', 
        json={
            'email': test_user['email'],
            'password': 'WrongPass123!'
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid email or password' in data['error']

def test_login_nonexistent_user(client):
    """Test login with non-existent user."""
    response = client.post('/auth/login', 
        json={
            'email': 'nonexistent@example.com',
            'password': 'SomePass123!'
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'error' in data
    assert 'Invalid email or password' in data['error']

def test_login_invalid_json(client):
    """Test login with invalid JSON payload."""
    response = client.post('/auth/login', 
        data='invalid json',
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data

def test_login_missing_fields(client):
    """Test login with missing fields."""
    # Test with empty payload
    response = client.post('/auth/login', 
        json={},
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 400
    
    # Test with missing password
    response = client.post('/auth/login', 
        json={'email': 'test@example.com'},
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 400
    
    # Test with missing email
    response = client.post('/auth/login', 
        json={'password': 'TestPass123!'},
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 400 

def test_login_case_insensitive_email(client, test_user):
    """Test that login works with different email casing."""
    response = client.post('/auth/login',
        json={
            'email': test_user['email'].upper(),  # Use uppercase email
            'password': test_user['password']
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['user']['email'] == test_user['email'].lower()

def test_login_email_with_whitespace(client, test_user):
    """Test login with extra whitespace in email."""
    response = client.post('/auth/login',
        json={
            'email': f"  {test_user['email']}  ",  # Add whitespace
            'password': test_user['password']
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['user']['email'] == test_user['email']

def test_login_password_with_whitespace(client, test_user):
    """Test that password with whitespace fails."""
    response = client.post('/auth/login',
        json={
            'email': test_user['email'],
            'password': f" {test_user['password']} "  # Add whitespace
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 401
    data = json.loads(response.data)
    assert 'Invalid email or password' in data['error']

def test_login_very_long_credentials(client):
    """Test login with very long email and password."""
    long_email = 'a' * 500 + '@example.com'  # Very long local part
    long_password = 'P@ssw0rd' * 100  # Very long password
    
    response = client.post('/auth/login',
        json={
            'email': long_email,
            'password': long_password
        },
        headers={'Content-Type': 'application/json'}
    )
    
    # Should return 400 as email is invalid
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data

def test_login_special_characters(client):
    """Test login with special characters in credentials."""
    # Create a user with special characters
    special_user = {
        'email': 'test.user+special@example.com',
        'password': 'P@ssw0rd!@#$%^&*()'
    }
    
    # Register the user
    with app.test_client() as c:
        c.post('/auth/signup',
            json={
                'email': special_user['email'],
                'password': special_user['password'],
                'confirm_password': special_user['password']
            },
            headers={'Content-Type': 'application/json'}
        )
    
    try:
        # Test login
        response = client.post('/auth/login',
            json={
                'email': special_user['email'],
                'password': special_user['password']
            },
            headers={'Content-Type': 'application/json'}
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['user']['email'] == special_user['email']
    
    finally:
        # Cleanup
        users_db.pop(special_user['email'].lower(), None)

def test_login_account_lockout(client, test_user):
    """Test account lockout after multiple failed attempts."""
    # Make 5 failed login attempts
    for _ in range(5):
        response = client.post('/auth/login',
            json={
                'email': test_user['email'],
                'password': 'WrongPass123!'
            },
            headers={'Content-Type': 'application/json'}
        )
        assert response.status_code == 401
    
    # 6th attempt should be locked out even with correct password
    response = client.post('/auth/login',
        json={
            'email': test_user['email'],
            'password': test_user['password']  # Correct password
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 429
    data = json.loads(response.data)
    assert 'locked' in data['error'].lower()

def test_login_lockout_reset_after_success(client, test_user):
    """Test that failed attempts reset after successful login."""
    # Make 3 failed attempts
    for _ in range(3):
        client.post('/auth/login',
            json={
                'email': test_user['email'],
                'password': 'WrongPass123!'
            },
            headers={'Content-Type': 'application/json'}
        )
    
    # Successful login
    response = client.post('/auth/login',
        json={
            'email': test_user['email'],
            'password': test_user['password']
        },
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 200
    
    # Should be able to attempt again immediately
    response = client.post('/auth/login',
        json={
            'email': test_user['email'],
            'password': 'WrongPass123!'
        },
        headers={'Content-Type': 'application/json'}
    )
    assert response.status_code == 401  # Not locked out

def test_login_token_expiry(client, test_user):
    """Test that the login token has correct expiry time."""
    response = client.post('/auth/login',
        json={
            'email': test_user['email'],
            'password': test_user['password']
        },
        headers={'Content-Type': 'application/json'}
    )
    
    assert response.status_code == 200
    data = json.loads(response.data)
    
    # Decode token without verification
    token_data = jwt.decode(
        data['token'],
        options={"verify_signature": False}
    )
    
    # Check expiry time (should be 1 hour from now)
    assert 'exp' in token_data
    exp_time = token_data['exp']
    iat_time = token_data['iat']
    assert exp_time - iat_time == 3600  # 1 hour in seconds 