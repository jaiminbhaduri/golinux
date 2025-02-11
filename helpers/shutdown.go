package helpers

import (
	"fmt"
	"os"
)

func Shutdown() {
	fmt.Println("Shutdown called. Exiting the program.")

	// Perform cleanup tasks here if needed

	// Exit the program
	os.Exit(0)
}
