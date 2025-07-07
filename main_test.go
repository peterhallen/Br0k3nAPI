package main

import (
	"bytes"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// setupRouter initializes a new Gin router for testing and registers all handlers.
func setupRouter() *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.Default()

	// Reset the in-memory user store for each test run
	users = make(map[string]User)

	// Register all endpoints
	r.GET("/ping", pingHandler)
	r.POST("/register", registerHandler)
	r.POST("/login", loginHandler)
	r.GET("/profile/:userID", profileHandler)
	r.POST("/data", dataHandler)
	r.GET("/admin/secret", adminSecretHandler)
	r.GET("/leak/env", leakEnvHandler)
	r.GET("/redirect", redirectHandler)
	r.POST("/upload", uploadHandler)
	r.GET("/error", errorHandler)
	r.GET("/readfile", readfileHandler)

	return r
}

// TestPingHandler (Unit Test)
// Verifies the health check endpoint is functional.
func TestPingHandler(t *testing.T) {
	router := setupRouter()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/ping", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{"message":"pong"}`, w.Body.String())
}

// TestUserRegistrationAndLogin (Integration Test)
// Verifies the entire user registration and login flow.
func TestUserRegistrationAndLogin(t *testing.T) {
	router := setupRouter()

	// 1. Register a new user
	user := User{Username: "testuser", Password: "password123"}
	userJSON, _ := json.Marshal(user)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(userJSON))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.JSONEq(t, `{"message":"User registered"}`, w.Body.String())

	// 2. Log in with the new user
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(userJSON))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]string
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.NotEmpty(t, response["token"], "Token should not be empty")
}

// TestIdorVulnerability (Vulnerability Confirmation Test)
// Verifies that the IDOR vulnerability exists on the /profile endpoint.
func TestIdorVulnerability(t *testing.T) {
	router := setupRouter()

	// 1. Create two users
	userA := User{Username: "userA", Password: "passwordA"}
	userB := User{Username: "userB", Password: "passwordB"}
	users[userA.Username] = userA
	users[userB.Username] = userB

	// 2. Log in as userA to get a token
	userAJSON, _ := json.Marshal(userA)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(userAJSON))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	var tokenResponse map[string]string
	json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	token := tokenResponse["token"]

	// 3. Use userA's token to request userB's profile
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/profile/userB", nil)
	req.Header.Set("Authorization", token)
	router.ServeHTTP(w, req)

	// Assert that the request is successful (200 OK) and returns userB's data
	assert.Equal(t, http.StatusOK, w.Code)
	var profileResponse User
	json.Unmarshal(w.Body.Bytes(), &profileResponse)
	assert.Equal(t, userB.Username, profileResponse.Username)
	assert.Equal(t, userB.Password, profileResponse.Password) // Confirms plaintext password is returned
}

// TestBrokenAccessControl (Vulnerability Confirmation Test)
// Verifies that a non-admin user cannot access the admin secret, but an admin can.
func TestBrokenAccessControl(t *testing.T) {
	router := setupRouter()

	// 1. Create a regular user and an admin user
	user := User{Username: "regularuser", Password: "password"}
	admin := User{Username: "admin", Password: "adminpass"}
	users[user.Username] = user
	users[admin.Username] = admin

	// 2. Log in as regular user and get token
	userJSON, _ := json.Marshal(user)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/login", bytes.NewBuffer(userJSON))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	var tokenResponse map[string]string
	json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	userToken := tokenResponse["token"]

	// 3. Attempt to access admin secret as regular user (should fail)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/admin/secret", nil)
	req.Header.Set("Authorization", userToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)

	// 4. Log in as admin and get token
	adminJSON, _ := json.Marshal(admin)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("POST", "/login", bytes.NewBuffer(adminJSON))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)
	json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	adminToken := tokenResponse["token"]

	// 5. Access admin secret as admin (should succeed)
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/admin/secret", nil)
	req.Header.Set("Authorization", adminToken)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "FLAG-ADMIN-1337")
}

// TestPathTraversalVulnerability (Vulnerability Confirmation Test)
// Verifies the path traversal vulnerability by attempting to read a test file.
func TestPathTraversalVulnerability(t *testing.T) {
	router := setupRouter()

	// Create a temporary file to be read
	tmpfile, err := os.CreateTemp("", "test-*.txt")
	assert.NoError(t, err)
	defer os.Remove(tmpfile.Name()) // clean up

	expectedContent := "secret content"
	_, err = tmpfile.WriteString(expectedContent)
	assert.NoError(t, err)
	tmpfile.Close()

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/readfile?path="+tmpfile.Name(), nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, expectedContent, w.Body.String())
}

// TestInsecureFileUpload (Vulnerability Confirmation Test)
// Verifies that a file can be uploaded without validation.
func TestInsecureFileUpload(t *testing.T) {
	router := setupRouter()

	// Create a buffer to store our request body
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	// Create a part for the file
	part, err := writer.CreateFormFile("file", "test.txt")
	assert.NoError(t, err)
	_, err = io.WriteString(part, "this is a test file")
	assert.NoError(t, err)
	writer.Close()

	// Make the request
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("POST", "/upload", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	router.ServeHTTP(w, req)

	// Assert the response
	assert.Equal(t, http.StatusOK, w.Code)
	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	assert.Equal(t, "File uploaded", response["message"])
	assert.Equal(t, "/tmp/test.txt", response["filename"])

	// Clean up the uploaded file
	os.Remove(filepath.Join("/tmp", "test.txt"))
}
