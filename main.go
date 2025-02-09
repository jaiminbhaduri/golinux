package main

import (
	"io"
	"log"
	"os"

	"github.com/jaiminbhaduri/golinux/helpers"
	"github.com/jaiminbhaduri/golinux/routes"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// In case of error, shut down
	defer helpers.Shutdown()

	if err := godotenv.Load(".env"); err != nil {
		log.Fatal("Error loading env file")
	}

	ip := os.Getenv("IP")
	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	os.Mkdir("/var/log/golinux", 0750)

	// Logging to a file.
	f, _ := os.Create("/var/log/golinux/access.log")
	gin.DefaultWriter = io.MultiWriter(f)

	router := gin.Default()
	router.SetTrustedProxies([]string{ip})

	//router.Use(middleware.Errorlogs())

	routes.UserRoutes(router)

	router.Run(":" + port)
}
