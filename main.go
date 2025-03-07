package main

import (
	"io"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jaiminbhaduri/golinux/config"
	"github.com/jaiminbhaduri/golinux/db"
	"github.com/jaiminbhaduri/golinux/middleware"
	"github.com/jaiminbhaduri/golinux/routes"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// In case of termination, clean up and shut down
	defer config.Shutdown()

	if err := godotenv.Load(".env"); err != nil {
		log.Fatal("Error loading env file")
	}

	// Connect db
	if err := db.Initdb(); err != nil {
		log.Fatal(err)
	}

	ip := os.Getenv("IP")
	port := os.Getenv("PORT")
	if port == "" {
		port = "9999"
	}

	os.Mkdir("/var/log/golinux", 0750)

	// Logging to a file
	// Open the log file in append mode
	f, err := os.OpenFile("/var/log/golinux/access.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal("Failed to open log file:", err)
	}
	defer f.Close()

	gin.DefaultWriter = io.MultiWriter(f)
	gin.SetMode(gin.ReleaseMode)

	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery(), middleware.ApiLogger())
	router.SetTrustedProxies([]string{ip})

	//router.Use(middleware.Errorlogs())

	routes.UserRoutes(router)

	// Run the server in a goroutine
	go func() {
		if err := router.Run(ip + ":" + port); err != nil {
			log.Fatal(err)
		}
	}()

	// Handle shutdown signals (Ctrl+C, kill command)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	log.Println("Server started on port", port)

	// Block until signal is received
	sig := <-sigChan
	log.Println("Received signal:", sig)
}
