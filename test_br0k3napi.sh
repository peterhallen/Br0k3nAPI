#!/bin/bash

BASE_URL="http://localhost:8888"
USERNAME="alice"
PASSWORD="1234"

# Register user
echo "\n== Registering user =="
curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"'$USERNAME'","password":"'$PASSWORD'"}' | tee /tmp/register_response.json

# Login user
echo "\n== Logging in =="
TOKEN=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"'$USERNAME'","password":"'$PASSWORD'"}' | jq -r .token)
echo "Token: $TOKEN"

# Get profile (IDOR)
echo "\n== Getting profile for $USERNAME =="
curl -s -X GET "$BASE_URL/profile/$USERNAME" \
    -H "Authorization: $TOKEN" | tee /tmp/profile_response.json

# Submit data (XSS/SQLi)
echo "\n== Submitting data (XSS/SQLi) =="
curl -s -X POST "$BASE_URL/data" \
    -H "Authorization: $TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"input":"<script>alert(1)</script> OR 1=1"}' | tee /tmp/data_response.json

# Try admin secret as non-admin
echo "\n== Trying admin secret as non-admin =="
curl -s -X GET "$BASE_URL/admin/secret" \
    -H "Authorization: $TOKEN" | tee /tmp/admin_response.json

# Register and login as admin
ADMIN_USER="admin"
ADMIN_PASS="adminpass"
echo "\n== Registering admin user =="
curl -s -X POST "$BASE_URL/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"'$ADMIN_USER'","password":"'$ADMIN_PASS'"}' | tee /tmp/register_admin_response.json

echo "\n== Logging in as admin =="
ADMIN_TOKEN=$(curl -s -X POST "$BASE_URL/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"'$ADMIN_USER'","password":"'$ADMIN_PASS'"}' | jq -r .token)
echo "Admin Token: $ADMIN_TOKEN"

echo "\n== Getting admin secret as admin =="
curl -s -X GET "$BASE_URL/admin/secret" \
    -H "Authorization: $ADMIN_TOKEN" | tee /tmp/admin_secret_response.json

echo "\n== Done ==" 