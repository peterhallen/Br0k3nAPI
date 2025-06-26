// Package main Br0K3nAPI demonstrates an intentionally vulnerable API for pen testing.
//
// @title Br0K3nAPI
// @version 1.0
// @description Intentionally vulnerable API for pen testing tools (ZAP, BurpSuite, etc.)
// @host localhost:8888
// @BasePath /
package main

import (
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	_ "Br0K3nAPI/docs"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// In-memory user store (username -> User)
var users = map[string]User{}

// Weak JWT secret (intentional flaw)
var jwtSecret = []byte("secret")

// User struct
// Note: Passwords are stored in plaintext (intentional flaw)
type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// @Summary Health check
// @Description Returns pong
// @Tags health
// @Success 200 {object} map[string]string
// @Router /ping [get]
func pingHandler(c *gin.Context) {
	c.JSON(200, gin.H{"message": "pong"})
}

// @Summary Register a new user
// @Description Registers a user with a weak password policy and verbose errors
// @Tags auth
// @Accept json
// @Produce json
// @Param user body User true "User credentials"
// @Success 201 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /register [post]
func registerHandler(c *gin.Context) {
	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	if len(req.Password) < 4 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password too short (min 4 chars)"})
		return
	}
	if _, exists := users[req.Username]; exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists"})
		return
	}
	users[req.Username] = req
	c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
}

// @Summary Login
// @Description Authenticates a user and returns a JWT (with weak secret)
// @Tags auth
// @Accept json
// @Produce json
// @Param user body User true "User credentials"
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /login [post]
func loginHandler(c *gin.Context) {
	var req User
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	user, exists := users[req.Username]
	if !exists || user.Password != req.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": req.Username,
		"exp":      time.Now().Add(time.Hour * 1).Unix(),
	})
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token: " + err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"token": tokenString})
}

// @Summary Get user profile
// @Description Returns the profile for any user by userID (username). Demonstrates IDOR vulnerability.
// @Tags user
// @Produce json
// @Param userID path string true "User ID (username)"
// @Success 200 {object} User
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Security ApiKeyAuth
// @Router /profile/{userID} [get]
func profileHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	userID := c.Param("userID")
	user, exists := users[userID]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// @Summary Submit data
// @Description Echoes user input, vulnerable to XSS and SQLi (no validation)
// @Tags data
// @Accept json
// @Produce json
// @Param data body map[string]string true "Data to submit"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Security ApiKeyAuth
// @Router /data [post]
func dataHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	var req map[string]string
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()})
		return
	}
	if val, ok := req["input"]; ok {
		fakeQuery := "SELECT * FROM data WHERE input = '" + val + "'"
		c.JSON(http.StatusOK, gin.H{"echo": val, "query": fakeQuery})
		return
	}
	c.JSON(http.StatusOK, gin.H{"echo": req})
}

// @Summary Admin secret
// @Description Returns admin-only info, but only checks for username == 'admin' in JWT (broken access control)
// @Tags admin
// @Produce json
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Security ApiKeyAuth
// @Router /admin/secret [get]
func adminSecretHandler(c *gin.Context) {
	tokenString := c.GetHeader("Authorization")
	if tokenString == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		return
	}
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		return
	}
	username, _ := claims["username"].(string)
	if strings.ToLower(username) != "admin" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not admin"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"secret": "The admin flag is: FLAG-ADMIN-1337"})
}

// @Summary Leak environment variables
// @Description Returns all environment variables (Sensitive Data Exposure)
// @Tags vuln
// @Produce json
// @Success 200 {object} map[string]string
// @Router /leak/env [get]
func leakEnvHandler(c *gin.Context) {
	envs := os.Environ()
	result := map[string]string{}
	for _, e := range envs {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			result[parts[0]] = parts[1]
		}
	}
	c.JSON(http.StatusOK, result)
}

// @Summary Unvalidated redirect
// @Description Redirects to a user-supplied URL (Open Redirect)
// @Tags vuln
// @Produce plain
// @Param url query string true "URL to redirect to"
// @Success 302 {string} string "redirect"
// @Router /redirect [get]
func redirectHandler(c *gin.Context) {
	url := c.Query("url")
	c.Redirect(http.StatusFound, url)
}

// @Summary Insecure file upload
// @Description Uploads a file without validation (no type/size check)
// @Tags vuln
// @Accept multipart/form-data
// @Produce json
// @Param file formData file true "File to upload"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /upload [post]
func uploadHandler(c *gin.Context) {
	file, header, err := c.Request.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "No file uploaded: " + err.Error()})
		return
	}
	defer file.Close()
	bytes, err := ioutil.ReadAll(file)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read file: " + err.Error()})
		return
	}
	filename := "/tmp/" + header.Filename
	ioutil.WriteFile(filename, bytes, 0644)
	c.JSON(http.StatusOK, gin.H{"message": "File uploaded", "filename": filename, "size": len(bytes)})
}

// @Summary Verbose error
// @Description Returns a stack trace or internal error (Verbose Error Message)
// @Tags vuln
// @Produce json
// @Router /error [get]
func errorHandler(c *gin.Context) {
	defer func() {
		if r := recover(); r != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "panic: ", "stack": r})
		}
	}()
	panic("This is a test panic for verbose error message!")
}

// @Summary Path traversal
// @Description Reads a file from disk based on user input (no sanitization)
// @Tags vuln
// @Produce plain
// @Param path query string true "Path to file"
// @Success 200 {string} string "file contents"
// @Failure 400 {object} map[string]string
// @Router /readfile [get]
func readfileHandler(c *gin.Context) {
	path := c.Query("path")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.String(http.StatusOK, string(data))
}

func main() {
	r := gin.Default()

	// CORS misconfiguration: allow all origins
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		c.Next()
	})

	// Insecure HTTP headers
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("X-Frame-Options", "ALLOWALL")
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("Server", "Br0K3nAPI")
		c.Next()
	})

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

	// Swagger docs route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.Run(":8888")
}
