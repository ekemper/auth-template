# Auth Template

A bare bones Flask API with a health check endpoint.

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

## Usage

To access environment variables in the code:

```python
import os

secret_key = os.getenv('SECRET_KEY')
api_key = os.getenv('API_KEY')
```

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Running the API

To run the development server:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## Endpoints

- Health Check: `GET /health`
  - Returns the API status