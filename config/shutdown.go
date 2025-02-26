package config

import (
	"log"
	"os"

	"github.com/jaiminbhaduri/golinux/db"
)

func Shutdown() {
	log.Println("Shutdown called. Exiting the program.")

	// Perform cleanup tasks here if needed
	db.CloseDB()

	// Exit the program
	os.Exit(0)
}
