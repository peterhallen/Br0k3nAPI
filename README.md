# Br0K3nAPI

Br0K3nAPI is an intentionally vulnerable REST API written in Go, designed for automated penetration testing and security tool evaluation (e.g., OWASP ZAP, BurpSuite, etc.).

## Purpose

This project is for learning, testing, and demonstrating the capabilities of security tools against common API vulnerabilities. **Do not deploy in production!**

## Features & Vulnerabilities

- JWT authentication (with flaws)
- User registration and login
- Profile endpoint (IDOR)
- Admin-only endpoint (broken access control)
- Data submission endpoint (XSS, SQLi, etc.)
- Verbose error messages
- CORS misconfiguration
- Insecure HTTP headers
- No rate limiting
- **Sensitive Data Exposure**: Leaks environment variables
- **Unvalidated Redirect**: Open redirect endpoint
- **Insecure File Upload**: No validation on file type or size
- **Path Traversal**: Reads arbitrary files from disk

## Endpoints

| Method | Path              | Description                        |
|--------|-------------------|------------------------------------|
| POST   | /register         | Register a new user                |
| POST   | /login            | Login and get JWT                  |
| GET    | /profile/:userID  | Get user profile (IDOR)            |
| POST   | /data             | Submit data (XSS/SQLi)             |
| GET    | /admin/secret     | Admin-only info                    |
| GET    | /ping             | Health check                       |
| GET    | /leak/env         | Leak environment variables         |
| GET    | /redirect         | Unvalidated redirect               |
| POST   | /upload           | Insecure file upload               |
| GET    | /error            | Verbose error message              |
| GET    | /readfile         | Path traversal (read file)         |

## Vulnerabilities Present

- **IDOR**: Insecure Direct Object Reference on `/profile/:userID`
- **Broken Access Control**: `/admin/secret` only checks username in JWT
- **XSS/SQLi**: `/data` endpoint echoes input and simulates SQL query
- **Sensitive Data Exposure**: `/leak/env` leaks all environment variables
- **Open Redirect**: `/redirect` redirects to user-supplied URL
- **Insecure File Upload**: `/upload` allows any file, no checks
- **Verbose Error**: `/error` returns stack trace on panic
- **Path Traversal**: `/readfile` reads arbitrary files from disk
- **CORS Misconfiguration**: Allows all origins
- **Insecure HTTP Headers**: Weak or missing security headers
- **No Rate Limiting**: Brute force and abuse possible
- **Weak JWT Secret**: JWT secret is hardcoded and weak
- **Plaintext Passwords**: User passwords stored in plaintext

## Getting Started

### Prerequisites
- Go 1.20+
- [swag](https://github.com/swaggo/swag) for Swagger docs
- [jq](https://stedolan.github.io/jq/) for the test script

### Install & Run
```sh
git clone https://github.com/yourusername/Br0K3nAPI.git
cd Br0K3nAPI
go mod tidy
swag init
go run main.go
```

The API will be available at `http://localhost:8888`.

### Swagger UI

Interactive API docs at: [http://localhost:8888/swagger/index.html](http://localhost:8888/swagger/index.html)

## Usage

Use tools like OWASP ZAP, BurpSuite, or Insomnia to scan and enumerate vulnerabilities. Try to:
- Bypass authentication
- Exploit IDOR
- Inject SQL/XSS payloads
- Abuse admin endpoints
- Upload malicious files
- Leak environment variables
- Exploit open redirect and path traversal

## Test Script

A shell script `test_br0k3napi.sh` is provided to automate testing of key endpoints. Requires `jq`.

```sh
chmod +x test_br0k3napi.sh
./test_br0k3napi.sh
```

## Disclaimer

This project is for educational and testing purposes only. Do not use in production or expose to the public internet. 