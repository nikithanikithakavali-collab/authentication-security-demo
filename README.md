
# Authentication Security Demo

## Objective
Implement defensive authentication controls and demonstrate them with automated tests.

## Features
- Password hashing with Node.js scrypt
- Server-side input validation
- Secure session cookies
- Logout and session expiry
- Login rate limiting
- Generic authentication error messages
- Automated tests

## Technologies
- Node.js
- JavaScript
- GitHub

## Run the application
npm start

## Run automated tests
npm test

## Security Note
This is an educational project. User accounts and sessions
are stored in memory and reset when the server restarts.
Production applications require persistent storage,
CSRF protection, HTTPS, and stronger shared rate limiting.
Never commit passwords, API keys, or sensitive information.
