# Secure Login System

A secure web-based login system built with Flask, implementing industry-standard
security practices for user authentication.

## Features

- **User Registration & Login** with bcrypt password hashing
- **Input Validation** for username, email, and password strength
- **SQL Injection Protection** via parameterized queries (SQLite)
- **Session Management** with secure logout
- **Optional Two-Factor Authentication (2FA)** using TOTP (Google Authenticator / Authy compatible)

## Tech Stack

- Python 3 + Flask
- SQLite (database)
- bcrypt (password hashing)
- pyotp + qrcode (2FA implementation)

## Installation

```bash
git clone https://github.com/<your-username>/secure-login-system.git
cd secure-login-system
pip install -r requirements.txt
python app.py
```

The app will run at `http://127.0.0.1:5000`

## Usage

1. **Register** a new account (username, email, strong password)
2. **Login** with your credentials
3. From the dashboard, optionally **enable 2FA**:
   - Scan the displayed QR code with Google Authenticator or Authy
   - On future logins, you'll be prompted for a 6-digit code
4. **Logout** securely from the dashboard

## Security Measures Implemented

| Feature | Implementation |
|---|---|
| Password Storage | bcrypt hashing with salt |
| SQL Injection Prevention | Parameterized SQL queries throughout |
| Input Validation | Regex validation for username, email, password strength |
| Session Management | Flask sessions with secure logout (session.clear()) |
| Two-Factor Authentication | TOTP-based (RFC 6238), QR code provisioning |

## Password Requirements

- Minimum 8 characters
- At least 1 uppercase letter
- At least 1 lowercase letter
- At least 1 digit

## Database Schema

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    totp_secret TEXT,
    two_fa_enabled INTEGER DEFAULT 0
);
```

## Expected Outcome

A secure login system with hashed passwords, input validation, session
management, and optional 2FA — significantly reducing unauthorized access
and protecting user accounts from common attacks such as SQL injection,
brute force, and credential theft.

## Future Improvements

- Rate limiting / account lockout after failed attempts
- Password reset via email
- HTTPS enforcement
- CSRF protection (Flask-WTF)
- Environment-based secret key management

## Disclaimer

This project is for educational purposes. For production deployment, use
environment variables for secrets, enable HTTPS, and add CSRF protection.