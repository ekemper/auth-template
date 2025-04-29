"""
Tests for the /health endpoint.
"""
import pytest
from flask import json

def test_health_check(client):
    """Test health check endpoint"""
    response = client.get('/health')
    assert response.status_code == 200
    assert response.json['status'] == 'healthy'
    assert 'message' in response.json
    assert 'API is running' in response.json['message'] 