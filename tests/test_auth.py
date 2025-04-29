import pytest
import jwt
import time
from datetime import datetime, timedelta
import json

class TestSignup:
    """Test cases for the signup endpoint."""

    def test_successful_signup(self, client):
        """Test successful user registration."""
        response = client.post('/auth/signup', json={
            'email': 'newuser@example.com',
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        })
        
        assert response.status_code == 201
        data = json.loads(response.data)
        assert 'token' in data
        assert 'user' in data
        assert data['user']['email'] == 'newuser@example.com'
        assert 'user_id' in data['user']

    def test_signup_existing_email(self, client, registered_user):
        """Test signup with an already registered email."""
        response = client.post('/auth/signup', json={
            'email': registered_user['email'],
            'password': 'NewPass123!',
            'confirm_password': 'NewPass123!'
        })
        
        assert response.status_code == 400
        assert b'Email already registered' in response.data

    @pytest.mark.parametrize('email', [
        'invalid-email',
        'missing@domain',
        '@nodomain.com',
        'spaces in@email.com',
        '',
        None
    ])
    def test_signup_invalid_email(self, client, email):
        """Test signup with invalid email formats."""
        response = client.post('/auth/signup', json={
            'email': email,
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data

    @pytest.mark.parametrize('password,confirm,expected_error', [
        ('short1!', 'short1!', 'Password must be at least 8 characters'),
        ('nospecial123', 'nospecial123', 'must contain at least one special character'),
        ('NoNumbers!!', 'NoNumbers!!', 'must contain at least one number'),
        ('12345678!', '12345678!', 'must contain at least one letter'),
        ('SecurePass123!', 'DifferentPass123!', 'Passwords do not match'),
        ('', '', 'All fields are required'),
        (None, None, 'All fields are required')
    ])
    def test_signup_invalid_password(self, client, password, confirm, expected_error):
        """Test signup with various invalid password scenarios."""
        response = client.post('/auth/signup', json={
            'email': 'newuser@example.com',
            'password': password,
            'confirm_password': confirm
        })
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
        assert expected_error.lower() in data['error'].lower()

    def test_signup_missing_fields(self, client):
        """Test signup with missing fields."""
        response = client.post('/auth/signup', json={})
        assert response.status_code == 400
        
        response = client.post('/auth/signup', json={'email': 'test@example.com'})
        assert response.status_code == 400

    def test_signup_invalid_json(self, client):
        """Test signup with invalid JSON payload."""
        response = client.post('/auth/signup', data='invalid json')
        assert response.status_code == 400

    def test_signup_case_insensitive_email(self, client, registered_user):
        """Test that email comparison is case-insensitive."""
        upper_email = registered_user['email'].upper()
        response = client.post('/auth/signup', json={
            'email': upper_email,
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        })
        
        assert response.status_code == 400
        assert b'Email already registered' in response.data

class TestLogin:
    """Test cases for the login endpoint."""

    def test_successful_login(self, client, registered_user):
        """Test successful login."""
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': registered_user['password']
        })
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'token' in data
        assert 'user' in data
        assert data['user']['email'] == registered_user['email']
        
        # Verify JWT token
        token = data['token']
        decoded = jwt.decode(token, 'test-secret-key-for-testing-only', algorithms=['HS256'])
        assert decoded['user_id'] == registered_user['user_id']
        assert decoded['email'] == registered_user['email']
        assert 'exp' in decoded
        assert 'iat' in decoded
        assert 'jti' in decoded

    def test_login_nonexistent_user(self, client):
        """Test login with non-existent user."""
        response = client.post('/auth/login', json={
            'email': 'nonexistent@example.com',
            'password': 'SecurePass123!'
        })
        
        assert response.status_code == 401
        assert b'Invalid email or password' in response.data

    def test_login_wrong_password(self, client, registered_user):
        """Test login with wrong password."""
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': 'WrongPass123!'
        })
        
        assert response.status_code == 401
        assert b'Invalid email or password' in response.data

    def test_login_case_insensitive_email(self, client, registered_user):
        """Test that login email is case-insensitive."""
        upper_email = registered_user['email'].upper()
        response = client.post('/auth/login', json={
            'email': upper_email,
            'password': registered_user['password']
        })
        
        assert response.status_code == 200

    def test_login_account_lockout(self, client, registered_user):
        """Test account lockout after multiple failed attempts."""
        # Make 5 failed login attempts
        for _ in range(5):
            response = client.post('/auth/login', json={
                'email': registered_user['email'],
                'password': 'WrongPass123!'
            })
            assert response.status_code == 401

        # Try one more time - should be locked out
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': registered_user['password']  # Even with correct password
        })
        
        assert response.status_code == 429
        assert b'Account temporarily locked' in response.data

    @pytest.mark.parametrize('payload', [
        {},  # Empty payload
        {'email': 'test@example.com'},  # Missing password
        {'password': 'SecurePass123!'},  # Missing email
        None  # No payload
    ])
    def test_login_missing_fields(self, client, payload):
        """Test login with missing fields."""
        response = client.post('/auth/login', json=payload)
        assert response.status_code == 400

    def test_login_invalid_json(self, client):
        """Test login with invalid JSON payload."""
        response = client.post('/auth/login', data='invalid json')
        assert response.status_code == 400

    def test_login_reset_failed_attempts(self, client, registered_user):
        """Test that failed attempts reset after successful login."""
        # Make 3 failed attempts
        for _ in range(3):
            response = client.post('/auth/login', json={
                'email': registered_user['email'],
                'password': 'WrongPass123!'
            })
            assert response.status_code == 401

        # Successful login
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': registered_user['password']
        })
        assert response.status_code == 200

        # Failed attempts should be reset - can try again
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': 'WrongPass123!'
        })
        assert response.status_code == 401  # Not locked out

    def test_login_token_expiration(self, client, registered_user):
        """Test that JWT token has correct expiration time."""
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': registered_user['password']
        })
        
        data = json.loads(response.data)
        token = data['token']
        decoded = jwt.decode(token, 'test-secret-key-for-testing-only', algorithms=['HS256'])
        
        # Check expiration time (should be 1 hour)
        exp_time = datetime.fromtimestamp(decoded['exp'])
        iat_time = datetime.fromtimestamp(decoded['iat'])
        assert (exp_time - iat_time) == timedelta(hours=1)

    def test_login_cookie_settings(self, client, registered_user):
        """Test secure cookie settings in production mode."""
        # Temporarily set FLASK_ENV to production
        import os
        original_env = os.getenv('FLASK_ENV')
        os.environ['FLASK_ENV'] = 'production'
        
        try:
            response = client.post('/auth/login', json={
                'email': registered_user['email'],
                'password': registered_user['password']
            })
            
            assert response.status_code == 200
            # Check for secure cookie
            cookies = response.headers.getall('Set-Cookie')
            assert any('auth_token' in cookie for cookie in cookies)
            assert any('HttpOnly' in cookie for cookie in cookies)
            assert any('Secure' in cookie for cookie in cookies)
            assert any('SameSite=Strict' in cookie for cookie in cookies)
        
        finally:
            # Restore original environment
            if original_env:
                os.environ['FLASK_ENV'] = original_env
            else:
                del os.environ['FLASK_ENV'] 