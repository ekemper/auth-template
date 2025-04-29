# Auth Template

A bare bones Flask API with JWT authentication, including signup and login endpoints.

## Environment Variables Setup

This project uses environment variables for configuration. Follow these steps to set up:

1. Copy the example environment file to create your own:
   ```bash
   cp example.env .env
   ```

2. Edit the `.env` file and replace the placeholder values with your actual configuration:
   ```
   FLASK_ENV=development
   FLASK_DEBUG=1
   SECRET_KEY=your-super-secret-key-here
   API_KEY=your-api-key-here
   ```

   **Important**: Never commit the `.env` file to version control. It's already added to `.gitignore`.

3. The application will automatically load these environment variables when it starts using python-dotenv.

## Authentication Endpoints

### Sign Up
- **Endpoint**: `POST /auth/signup`
- **Rate Limit**: 3 requests per minute, 20 per hour
- **Request Body**:
  ```json
  {
      "email": "user@example.com",
      "password": "SecurePass123!",
      "confirm_password": "SecurePass123!"
  }
  ```
- **Success Response** (201 Created):
  ```json
  {
      "message": "User registered successfully",
      "token": "your.jwt.token",
      "user": {
          "email": "user@example.com",
          "user_id": "uuid-string"
      }
  }
  ```
- **Error Responses**:
  - 400 Bad Request:
    ```json
    {
        "error": "Error message here"
    }
    ```
  - 429 Too Many Requests:
    ```json
    {
        "error": "Rate limit exceeded"
    }
    ```

Password Requirements:
- Minimum 8 characters
- At least one letter
- At least one number
- At least one special character (@$!%*#?&)

### Login
- **Endpoint**: `POST /auth/login`
- **Rate Limit**: 5 requests per minute
- **Request Body**:
  ```json
  {
      "email": "user@example.com",
      "password": "your-password"
  }
  ```
- **Success Response** (200 OK):
  ```json
  {
      "token": "your.jwt.token",
      "user": {
          "email": "user@example.com",
          "user_id": "1"
      }
  }
  ```
- **Error Response** (400/401):
  ```json
  {
      "error": "Error message here"
  }
  ```

### Health Check
- **Endpoint**: `GET /health`
- **Rate Limit**: 10 requests per minute
- **Success Response** (200 OK):
  ```json
  {
      "status": "healthy",
      "message": "API is running"
  }
  ```

## Security Features

1. **Rate Limiting**
   - Signup: 3 requests per minute, 20 per hour
   - Login: 5 requests per minute
   - Health Check: 10 requests per minute

2. **Password Security**
   - Bcrypt hashing with salt
   - Complexity requirements enforced
   - Password confirmation on signup

3. **Email Validation**
   - Format validation
   - Deliverability check
   - Case-insensitive uniqueness check

4. **JWT Token Security**
   - 1-hour expiration
   - Secure HttpOnly cookies in production
   - CSRF protection with SameSite cookie policy

5. **Request Security**
   - CORS protection
   - Security headers (HSTS, CSP, etc.)
   - Request ID tracking
   - Input sanitization

6. **Brute Force Protection**
   - Account lockout after 5 failed attempts
   - 15-minute lockout period
   - Failed attempt tracking

## Testing

### Setting Up the Test Environment

1. Create a `.env.test` file with test configuration:
```bash
FLASK_ENV=testing
FLASK_DEBUG=0
SECRET_KEY=test-secret-key-for-testing-only
ALLOWED_ORIGINS=http://localhost:5000
API_KEY=test-api-key

# Rate limiting configuration
RATELIMIT_STORAGE_URL=memory://
RATELIMIT_DEFAULT=1000/day
RATELIMIT_LOGIN=1000/minute
RATELIMIT_SIGNUP=1000/minute
```

2. Install test dependencies:
```bash
pip install -r requirements.txt
```

### Running Tests

Run all tests with coverage report:
```bash
pytest tests/ -v --cov=app --cov-report=term-missing
```

Run specific test file:
```bash
pytest tests/test_auth.py -v
```

Run specific test case:
```bash
pytest tests/test_auth.py::TestSignup::test_successful_signup -v
```

### Test Coverage

The test suite includes comprehensive tests for both the signup and login endpoints:

#### Signup Endpoint Tests
- Successful user registration
- Duplicate email registration attempts
- Invalid email formats
- Password complexity requirements
- Password confirmation matching
- Missing required fields
- Invalid JSON payloads
- Case-insensitive email validation

#### Login Endpoint Tests
- Successful login
- Non-existent user login attempts
- Wrong password attempts
- Case-insensitive email login
- Account lockout after failed attempts
- Missing fields validation
- Invalid JSON payloads
- Failed attempts reset after successful login
- JWT token expiration verification
- Secure cookie settings in production

### Test Structure
```
tests/
├── conftest.py           # Test fixtures and configuration
└── test_auth.py         # Authentication endpoint tests
```

### Continuous Integration

To integrate these tests into your CI pipeline, you can use the following command:
```bash
pytest tests/ -v --cov=app --cov-report=xml --junitxml=test-results.xml
```

This will generate:
- Coverage report in XML format
- Test results in JUnit XML format

## Testing the API

You can test the endpoints using curl:

1. Sign Up:
```bash
curl -X POST http://localhost:5000/auth/signup \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!",
    "confirm_password": "SecurePass123!"
  }'
```

2. Login:
```bash
curl -X POST http://localhost:5000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Set up environment variables as described above.

4. Run the application:
```bash
python app.py
```

The API will be available at `http://localhost:5000`