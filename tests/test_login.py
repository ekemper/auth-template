"""
Tests for the /auth/login endpoint.
"""
import pytest
from flask import json

def test_login_success(client, registered_user):
    """Test successful login"""
    response = client.post('/auth/login', json={
        'email': registered_user['email'],
        'password': registered_user['password']
    })
    assert response.status_code == 200
    assert 'token' in response.json
    assert 'user' in response.json
    assert response.json['user']['email'] == registered_user['email']

def test_login_missing_fields(client):
    """Test login with missing required fields"""
    # Missing email
    response = client.post('/auth/login', json={
        'password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'Missing email or password' in response.json['error']

    # Missing password
    response = client.post('/auth/login', json={
        'email': 'user@example.com'
    })
    assert response.status_code == 400
    assert 'Missing email or password' in response.json['error']

def test_login_invalid_email(client):
    """Test login with invalid email format"""
    response = client.post('/auth/login', json={
        'email': 'notanemail',
        'password': 'SecurePass123!'
    })
    assert response.status_code == 400
    assert 'email' in response.json['error'].lower()

def test_login_wrong_password(client, registered_user):
    """Test login with incorrect password"""
    response = client.post('/auth/login', json={
        'email': registered_user['email'],
        'password': 'WrongPass123!'
    })
    assert response.status_code == 401
    assert 'Invalid email or password' in response.json['error']

def test_login_nonexistent_user(client):
    """Test login with non-existent user"""
    response = client.post('/auth/login', json={
        'email': 'nonexistent@example.com',
        'password': 'SecurePass123!'
    })
    assert response.status_code == 401
    assert 'Invalid email or password' in response.json['error']

def test_login_case_insensitive_email(client, registered_user):
    """Test that login is case insensitive for email"""
    response = client.post('/auth/login', json={
        'email': registered_user['email'].upper(),
        'password': registered_user['password']
    })
    assert response.status_code == 200
    assert 'token' in response.json

def test_login_invalid_json(client):
    """Test login with invalid JSON payload"""
    response = client.post('/auth/login',
        data='invalid json',
        content_type='application/json'
    )
    assert response.status_code == 400
    assert 'Invalid JSON payload' in response.json['error']

def test_login_account_lockout(client, registered_user):
    """Test account lockout after multiple failed attempts"""
    # Make 5 failed login attempts
    for _ in range(5):
        response = client.post('/auth/login', json={
            'email': registered_user['email'],
            'password': 'WrongPass123!'
        })
        assert response.status_code == 401

    # Next attempt should be locked out
    response = client.post('/auth/login', json={
        'email': registered_user['email'],
        'password': registered_user['password']
    })
    assert response.status_code == 429
    assert 'Account temporarily locked' in response.json['error'] 