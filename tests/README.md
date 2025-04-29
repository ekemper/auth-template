# Testing Documentation

This directory contains the test suite for the authentication service. The tests are written using pytest and cover both functionality and security aspects of the API.

## Directory Structure

```
tests/
├── __init__.py          # Test package initialization
├── conftest.py          # Test fixtures and configuration
├── test_api.py          # API endpoint tests
└── README.md           # This documentation
```

## Running Tests

### Basic Test Execution

Run all tests with verbose output:
```bash
pytest tests/ -v
```

Run tests with coverage report:
```bash
pytest --cov=app tests/
```

Generate test output log:
```bash
pytest tests/test_api.py -v > test_output.log
```

### Test Categories

#### Login Endpoint Tests
- Basic functionality:
  - Successful login with valid credentials
  - Failed login with wrong password
  - Failed login for non-existent user
  - Invalid JSON payload handling
  - Missing required fields validation

- Edge cases:
  - Case-insensitive email handling
  - Email with extra whitespace
  - Password with whitespace
  - Very long credentials
  - Special characters in credentials
  - Account lockout after multiple failed attempts
  - Lockout reset after successful login
  - Token expiration verification

#### Security Tests
- Rate limiting (disabled during tests)
- Password complexity requirements
- Account lockout protection
- JWT token validation
- Input sanitization
- CORS protection

## Test Configuration

### Environment Setup

1. Create a `.env.test` file with test-specific settings:
```env
FLASK_ENV=testing
FLASK_DEBUG=0
SECRET_KEY=test-secret-key
ALLOWED_ORIGINS=http://localhost:5000
RATELIMIT_ENABLED=False
RATELIMIT_STORAGE_URL=memory://
TESTING=True
```

2. The test environment automatically:
   - Disables rate limiting
   - Uses in-memory storage
   - Sets secure defaults for testing

### Test Fixtures

Key fixtures in `conftest.py`:
- `app`: Flask application instance configured for testing
- `client`: Test client for making requests
- `registered_user`: Pre-registered user for login tests

## Adding New Tests

When adding new tests:

1. Follow the existing pattern in `test_api.py`
2. Use descriptive test names that indicate the scenario being tested
3. Include both positive and negative test cases
4. Add appropriate assertions for response status and content
5. Document any new fixtures in `conftest.py`

Example test structure:
```python
def test_descriptive_name(client, fixture1, fixture2):
    # Setup
    test_data = {...}
    
    # Execute
    response = client.post('/endpoint', json=test_data)
    
    # Assert
    assert response.status_code == expected_status
    assert response.json['key'] == expected_value
```

## Best Practices

1. Keep tests independent and isolated
2. Clean up any test data after each test
3. Use meaningful test data that reflects real-world scenarios
4. Add comments for complex test logic
5. Group related tests using pytest classes

## Common Issues and Solutions

1. Rate limiting interfering with tests:
   - Ensure `RATELIMIT_ENABLED=False` in `.env.test`
   - Clear rate limit storage between tests

2. Test database conflicts:
   - Use unique test data for each test
   - Clean up test data in fixture teardown

3. JWT token issues:
   - Verify `SECRET_KEY` is set in test environment
   - Check token expiration settings

## Future Improvements

1. Add integration tests for:
   - Password reset flow
   - Email verification
   - User profile updates

2. Enhance coverage for:
   - Error handling paths
   - Edge cases in input validation
   - Security headers

3. Add performance tests for:
   - Concurrent user registration
   - Login under load
   - Rate limiting effectiveness

## Logging

Test output is logged to `test_output.log` when running:
```bash
pytest tests/test_api.py -v > test_output.log
```

The log file includes:
- Test execution results
- Detailed error messages
- Coverage information
- Timing data

## Continuous Integration

For CI environments:
1. Use `pytest.ini` configuration
2. Generate coverage reports
3. Save test artifacts
4. Set appropriate timeouts

## Support

For issues with the test suite:
1. Check this documentation
2. Review test output logs
3. Verify environment configuration
4. Check for recent changes in dependencies 