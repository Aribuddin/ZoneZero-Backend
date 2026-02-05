# ZoneZero Backend API

Backend API for ZoneZero AI Research Assistant.

## Setup

1. Clone this repository
2. Install dependencies: `pip install -r requirements.txt`
3. Copy `.env.example` to `.env` and fill in your API keys
4. Copy `serviceAccountKey.example.json` to `serviceAccountKey.json` with your Firebase credentials
5. Run: `python app.py`

## Deployment

This backend is designed to be deployed on [Render](https://render.com):

1. Create a new Web Service on Render
2. Connect this repository
3. Set environment variables (GEMINI_API_KEY, etc.)
4. Deploy!

## API Endpoints

- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `GET /api/auth/verify` - Verify token
- `POST /api/search` - Perform AI research
- `GET /api/history` - Get search history
- `GET /api/health` - Health check
