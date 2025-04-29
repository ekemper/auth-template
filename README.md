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
FLASK_ENV=development
SECRET_KEY=your-secret-key
ALLOWED_ORIGINS=http://localhost:3000
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
The project includes a comprehensive test suite. For detailed testing documentation, see [tests/README.md](tests/README.md).

Quick start:
```bash
# Run all tests
pytest tests/ -v

# Run tests with coverage
pytest --cov=app tests/

# Run tests with detailed logging
pytest tests/test_api.py -v > test_output.log
```

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