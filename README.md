  **FastAPI Expense Tracker**

A REST API for tracking personal expenses, built with FastAPI and deployed on AWS EC2.

 🌐 Live Demo
**Base URL:** http://3.15.45.176:8000/docs

 🛠️ Tech Stack
- **FastAPI** — Python web framework
- **SQLAlchemy** — ORM for database management
- **SQLite** — Database
- **JWT Authentication** — Secure user auth
- **AWS EC2** — Cloud deployment

##  Features
- User registration & login with JWT tokens
- Create, read, update, delete expenses
- Each user sees only their own expenses

## 📡 API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /register | Register a new user |
| POST | /login | Login and get token |
| POST | /expenses | Create an expense |
| GET | /expenses | Get all expenses |
| GET | /expenses/{id} | Get single expense |
| PUT | /expenses/{id} | Update an expense |
| DELETE | /expenses/{id} | Delete an expense |

## ⚙️ Run Locally
```bash
git clone https://github.com/MAAZSHAHEEN/fastapi-expense-tracker.git
cd fastapi-expense-tracker
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```
