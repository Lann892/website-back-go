package main

import (
	"go-jwt/controllers"
	"go-jwt/initializers"
	"go-jwt/middleware"

	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnvVariables()
	initializers.ConnectToDb()
	initializers.SyncDatabase()
}

func main() {
	r := gin.Default()

	r.POST("/api/signup", controllers.Signup)
	r.POST("/api/login", controllers.Login)
	r.GET("/api/validate", middleware.RequireAuth, controllers.Validate)

	r.Run()
}
