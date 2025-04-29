"""
Tests for the /auth/signup endpoint.
"""
import pytest
from flask import json
from email_validator import validate_email, EmailNotValidError

def test_signup_success(client):
    """Test successful user registration"""
    response = client.post('/auth/signup', json={
        'email': 'newuser@example.com',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 201
    assert 'message' in response.json
    assert 'User registered successfully' in response.json['message']

def test_signup_missing_fields(client):
    """Test signup with missing required fields"""
    # Missing email
    response = client.post('/auth/signup', json={
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'All fields are required' in response.json['error']

    # Missing password
    response = client.post('/auth/signup', json={
        'email': 'user@example.com',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'All fields are required' in response.json['error']

    # Missing confirm_password
    response = client.post('/auth/signup', json={
        'email': 'user@example.com',
        'password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'All fields are required' in response.json['error']

def test_signup_invalid_email(client):
    """Test signup with invalid email formats"""
    invalid_emails = [
        'notanemail',
        'missing@domain',
        '@nodomain.com',
        'spaces in@email.com',
        'unicode@🦄.com'
    ]
    
    for email in invalid_emails:
        response = client.post('/auth/signup', json={
            'email': email,
            'password': 'SecurePass123!',
            'confirm_password': 'SecurePass123!'
        })
        assert response.status_code == 400
        # The exact error message will come from email_validator
        assert response.json['error']

def test_signup_password_mismatch(client):
    """Test signup with non-matching passwords"""
    response = client.post('/auth/signup', json={
        'email': 'user@example.com',
        'password': 'SecurePass123!',
        'confirm_password': 'DifferentPass123!'
    })
    assert response.status_code == 400
    assert 'Passwords do not match' in response.json['error']

def test_signup_weak_password(client):
    """Test signup with weak passwords"""
    test_cases = [
        ('short', 'Password must be at least 8 characters long'),
        ('123456789!', 'Password must contain at least one letter'),
        ('NoSpecialChar1', 'Password must contain at least one special character'),
        ('NoNumber!', 'Password must contain at least one number'),
        ('12345678!', 'Password must contain at least one letter')
    ]
    
    for password, expected_error in test_cases:
        response = client.post('/auth/signup', json={
            'email': 'user@example.com',
            'password': password,
            'confirm_password': password
        })
        assert response.status_code == 400
        assert expected_error in response.json['error']

def test_signup_duplicate_email(client):
    """Test signup with an already registered email"""
    # First registration
    response = client.post('/auth/signup', json={
        'email': 'duplicate@example.com',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 201

    # Attempt duplicate registration
    response = client.post('/auth/signup', json={
        'email': 'duplicate@example.com',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'Email already registered' in response.json['error']

def test_signup_invalid_json(client):
    """Test signup with invalid JSON payload"""
    response = client.post('/auth/signup', 
        data='invalid json',
        content_type='application/json'
    )
    assert response.status_code == 400
    assert 'Missing required fields' in response.json['error']

def test_signup_email_case_insensitive(client):
    """Test that email registration is case insensitive"""
    # Register with lowercase
    response = client.post('/auth/signup', json={
        'email': 'user@example.com',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 201

    # Try to register with uppercase
    response = client.post('/auth/signup', json={
        'email': 'USER@EXAMPLE.COM',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'Email already registered' in response.json['error']

def test_signup_email_whitespace(client):
    """Test that emails are trimmed of whitespace"""
    response = client.post('/auth/signup', json={
        'email': '  user@example.com  ',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 201

    # Try to register the same email without whitespace
    response = client.post('/auth/signup', json={
        'email': 'user@example.com',
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'Email already registered' in response.json['error']

def test_signup_long_inputs(client):
    """Test signup with very long inputs"""
    # Test with very long email
    long_email = 'a' * 256 + '@example.com'
    response = client.post('/auth/signup', json={
        'email': long_email,
        'password': 'SecurePass123!',
        'confirm_password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'email' in response.json['error'].lower()

    # Test with very long password
    response = client.post('/auth/signup', json={
        'email': 'valid@example.com',
        'password': 'A' * 1000 + '123!',
        'confirm_password': 'A' * 1000 + '123!'
    })
    assert response.status_code == 400
    # The error will come from password validation 