# Auth Template Application

This is a secure authentication template application built with Flask and React, ready for deployment on Heroku.

## Features

- Secure user authentication
- Rate limiting
- CORS support
- Email validation
- JSON Web Token (JWT) based authentication
- PostgreSQL database integration
- Modern React frontend

## Prerequisites

- Python 3.9+
- Node.js and npm
- PostgreSQL database (We recommend Neon for development)
- Heroku CLI

## Local Development Setup

1. Clone the repository:
```bash
git clone <your-repo-url>
cd auth-template
```

2. Set up Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Set up frontend:
```bash
cd frontend
npm install
npm run build
cd ..
```

4. Configure environment variables:
```bash
cp example.env .env
```
Edit `.env` with your configuration:
```
FLASK_APP=app.py
FLASK_ENV=development
DATABASE_URL=your_database_url
JWT_SECRET_KEY=your_secret_key
```

5. Run the application:
```bash
flask run
```

## Database Setup

We recommend using [Neon](https://neon.tech) for your PostgreSQL database needs. Here's how to set it up:

1. Create a free account at [neon.tech](https://neon.tech)
2. Create a new project
3. Get your connection string from the dashboard
4. Add the connection string to your `.env` file as `DATABASE_URL`

## Deployment to Heroku

1. Install the [Heroku CLI](https://devcenter.heroku.com/articles/heroku-cli)

2. Login to Heroku:
```bash
heroku login
```

3. Create a new Heroku app:
```bash
heroku create your-app-name
```

4. Set up PostgreSQL on Heroku:
```bash
heroku addons:create heroku-postgresql:mini
```

5. Configure environment variables:
```bash
heroku config:set JWT_SECRET_KEY=your_secret_key
heroku config:set FLASK_ENV=production
```

6. Deploy your application:
```bash
git push heroku main
```

7. Run database migrations (if any):
```bash
heroku run python manage.py db upgrade
```

## Project Structure

- `/app.py` - Main Flask application
- `/frontend/` - React frontend application
- `/tests/` - Test suite
- `/utils/` - Utility functions
- `Procfile` - Heroku deployment configuration

## Testing

Run the test suite:
```bash
pytest
```

For coverage report:
```bash
pytest --cov=.

## Security Considerations

- All passwords are hashed using bcrypt
- Rate limiting is implemented to prevent brute force attacks
- CORS is configured for security
- JWT tokens are used for secure authentication
- Environment variables are used for sensitive data

## License

[Your License Here]

## Contributing

[Your Contributing Guidelines]