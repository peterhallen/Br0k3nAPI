// Package main Br0K3nAPI demonstrates an intentionally vulnerable API for pen testing.
//
// @title Br0K3nAPI
// @version 1.0
// @description Intentionally vulnerable API for pen testing tools (ZAP, BurpSuite, etc.)
// @host localhost:8080
// @BasePath /
package main

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

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

	// TODO: Add Swagger docs and more endpoints

	r.Run(":8080") // listen and serve on 0.0.0.0:8080
}
