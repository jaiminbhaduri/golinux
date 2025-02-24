package config

import (
	"fmt"
	"os"

	"github.com/jaiminbhaduri/golinux/db"
)

func Shutdown() {
	fmt.Println("Shutdown called. Exiting the program.")

	// Perform cleanup tasks here if needed
	db.CloseDB()
	fmt.Println("DB closed")

	// Exit the program
	os.Exit(0)
}
