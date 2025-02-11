package helpers

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Function to verify the user's password
func VerifyPassword(username, password string) (bool, error) {
	// Open the /etc/shadow file
	file, err := os.Open("/etc/shadow")
	if err != nil {
		return false, err
	}
	defer file.Close()

	// Scan /etc/shadow to find the user's hashed password
	scanner := bufio.NewScanner(file)
	var hashedPassword string

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Split(line, ":")

		if fields[0] == username {
			hashedPassword = fields[1]
			break
		}
	}

	if hashedPassword == "" {
		return false, errors.New("no password found for user")
	}

	// Python script to compare password with shadow file hashed password
	cmd := exec.Command("python3", "-c", "import crypt; print(crypt.crypt(input(), input()))")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, err
	}

	// Write password and salt securely
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, password+"\n")
		io.WriteString(stdin, hashedPassword+"\n")
	}()

	var output bytes.Buffer
	cmd.Stdout = &output

	if err := cmd.Run(); err != nil {
		return false, err
	}

	// Compare hashes
	return strings.TrimSpace(output.String()) == hashedPassword, nil
}

func GetSudoUsers() ([]string, error) {
	// Open and read /etc/group file
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return []string{}, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var sudoUsers []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "sudo:") {
			parts := strings.Split(line, ":")

			if parts[3] != "" {
				sudoUsers = strings.Split(parts[3], ",")
			}

			break
		}
	}

	return sudoUsers, nil
}

func GetShells() ([]string, error) {
	// Open and read /etc/shells file
	data, err := os.ReadFile("/etc/shells")
	if err != nil {
		return []string{}, err
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var shells []string

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") {
			continue
		}

		shells = append(shells, line)
	}

	return shells, nil
}
