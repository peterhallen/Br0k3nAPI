// Package main Br0K3nAPI demonstrates an intentionally vulnerable API for pen testing.
//
// @title Br0K3nAPI
// @version 1.0
// @description Intentionally vulnerable API for pen testing tools (ZAP, BurpSuite, etc.)
// @host localhost:8888
// @BasePath /
package main

import (
	"net/http"
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
func main() {
	r := gin.Default()

	// Health check endpoint
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	// Swagger docs route
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// Registration endpoint
	// @Summary Register a new user
	// @Description Registers a user with a weak password policy and verbose errors
	// @Tags auth
	// @Accept json
	// @Produce json
	// @Param user body User true "User credentials"
	// @Success 201 {object} map[string]string
	// @Failure 400 {object} map[string]string
	// @Router /register [post]
	r.POST("/register", func(c *gin.Context) {
		var req User
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request: " + err.Error()}) // Verbose error
			return
		}
		if len(req.Password) < 4 { // Weak password policy
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password too short (min 4 chars)"})
			return
		}
		if _, exists := users[req.Username]; exists {
			c.JSON(http.StatusBadRequest, gin.H{"error": "User already exists"})
			return
		}
		users[req.Username] = req // Store plaintext password
		c.JSON(http.StatusCreated, gin.H{"message": "User registered"})
	})

	// Login endpoint
	// @Summary Login
	// @Description Authenticates a user and returns a JWT (with weak secret)
	// @Tags auth
	// @Accept json
	// @Produce json
	// @Param user body User true "User credentials"
	// @Success 200 {object} map[string]string
	// @Failure 401 {object} map[string]string
	// @Router /login [post]
	r.POST("/login", func(c *gin.Context) {
		var req User
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid request: " + err.Error()}) // Verbose error
			return
		}
		user, exists := users[req.Username]
		if !exists || user.Password != req.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}
		// Create JWT token (with weak secret)
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
	})

	// Profile endpoint (IDOR)
	// @Summary Get user profile
	// @Description Returns the profile for any user by userID (username). Demonstrates IDOR vulnerability.
	// @Tags user
	// @Produce json
	// @Param userID path string true "User ID (username)"
	// @Success 200 {object} User
	// @Failure 401 {object} map[string]string
	// @Failure 404 {object} map[string]string
	// @Security ApiKeyAuth
	r.GET("/profile/:userID", func(c *gin.Context) {
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
	})

	// TODO: Add more endpoints

	r.Run(":8888") // listen and serve on 0.0.0.0:8888
}
