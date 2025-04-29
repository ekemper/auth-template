# Auth Template

A secure authentication service template with robust testing.

## Features
- User registration and login
- JWT-based authentication
- Rate limiting
- Account lockout protection
- Secure password handling
- Comprehensive test suite

## Installation
```bash
# Clone the repository
git clone <repository-url>
cd auth-template

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy example environment file
cp example.env .env
```

## Configuration
Update the `.env` file with your settings:
```env
# Application settings
DEBUG=False  # Set to True for development debugging
TESTING=False  # Set to True for test environment
SECRET_KEY=your-secret-key-here

# Security settings
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5000
RATELIMIT_STORAGE_URL=memory://
```

## Running the Service
```bash
# Development mode
flask run

# Production mode
gunicorn app:app
```

## Testing
The project includes a comprehensive test suite organized by endpoint. Each endpoint has its own test file:

- `test_signup.py`: Tests for user registration
- `test_login.py`: Tests for user authentication
- `test_health.py`: Tests for health check endpoint

### Running Tests

```bash
# Run all tests with coverage report
pytest

# Run tests for a specific endpoint
pytest tests/test_signup.py
pytest tests/test_login.py
pytest tests/test_health.py

# Run a specific test function
pytest tests/test_signup.py::test_signup_success

# Run tests with specific marker
pytest -m signup
pytest -m login
pytest -m health

# Run tests with detailed output
pytest -v

# Run tests with coverage report
pytest --cov=app

# Run tests and generate HTML coverage report
pytest --cov=app --cov-report=html
```

### Test Configuration

Test settings are configured in `pytest.ini`:
- Verbose output enabled by default
- Coverage reporting enabled
- Test environment variables set
- Custom markers for each endpoint
- Logging configuration

### Test Environment

Tests use a separate configuration defined in `pytest.ini`:
- Rate limiting disabled
- In-memory storage
- Test-specific secret key
- Simplified CORS settings

For detailed testing documentation, see [tests/README.md](tests/README.md).

## API Documentation

### Authentication Endpoints

#### POST /auth/signup
Register a new user.
```json
{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!"
}
```

#### POST /auth/login
Login with existing credentials.
```json
{
    "email": "user@example.com",
    "password": "SecurePass123!"
}
```

## Security Features
- Password complexity requirements
- Rate limiting on all endpoints
- Account lockout after failed attempts
- Secure password hashing with bcrypt
- JWT token expiration
- CORS protection
- Security headers

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License
This project is licensed under the MIT License - see the LICENSE file for details.