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

## Endpoints

| Method | Path              | Description                |
|--------|-------------------|----------------------------|
| POST   | /register         | Register a new user        |
| POST   | /login            | Login and get JWT          |
| GET    | /profile/:userID  | Get user profile           |
| POST   | /data             | Submit data (echoes input) |
| GET    | /admin/secret     | Admin-only info            |
| GET    | /ping             | Health check               |

## Getting Started

### Prerequisites
- Go 1.20+
- [swag](https://github.com/swaggo/swag) for Swagger docs

### Install & Run
```sh
git clone https://github.com/yourusername/Br0K3nAPI.git
cd Br0K3nAPI
go mod tidy
swag init
go run main.go
```

The API will be available at `http://localhost:8080`.

### Swagger UI

Interactive API docs at: [http://localhost:8080/swagger/index.html](http://localhost:8080/swagger/index.html)

## Usage

Use tools like OWASP ZAP or BurpSuite to scan and enumerate vulnerabilities. Try to:
- Bypass authentication
- Exploit IDOR
- Inject SQL/XSS payloads
- Abuse admin endpoints

## Disclaimer

This project is for educational and testing purposes only. Do not use in production or expose to the public internet. 