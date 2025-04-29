import os
import pytest
from flask import Flask
from dotenv import load_dotenv
from app import create_app

@pytest.fixture(scope='session')
def app():
    """Create a Flask application for testing"""
    # Load test environment variables
    load_dotenv('.env.test')
    
    # Create the app with testing config
    app = create_app()
    app.config['TESTING'] = True
    app.config['RATELIMIT_ENABLED'] = False  # Explicitly disable rate limiting
    
    return app

@pytest.fixture
def client(app):
    """Create a test client for the app"""
    return app.test_client()

@pytest.fixture(autouse=True)
def clear_users(app):
    """Clear the users database before each test"""
    with app.app_context():
        app.users_db = {}  # Reset the in-memory user database
        yield
        app.users_db = {}  # Clean up after test

@pytest.fixture
def registered_user(client):
    """Create a test user and return their credentials"""
    user_data = {
        'email': 'test@example.com',
        'password': 'TestPass123!',
        'confirm_password': 'TestPass123!'
    }
    
    # Register the user
    response = client.post('/auth/signup', json=user_data)
    assert response.status_code == 201
    
    # Return the credentials (without confirm_password)
    return {
        'email': user_data['email'],
        'password': user_data['password']
    } 