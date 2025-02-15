package helpers

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/jaiminbhaduri/golinux/db"
	"github.com/jaiminbhaduri/golinux/models"
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
	shells := []string{"/usr/sbin/nologin"}

	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "#") {
			continue
		}

		shells = append(shells, line)
	}

	return shells, nil
}

func SetUserPasswd(user, password, cpassword *string) map[string]any {
	// Helper function to return error response quickly
	setError := func(msg string) map[string]any {
		return map[string]any{
			"error":     msg,
			"exit_code": 1,
		}
	}

	if *user == "" {
		return setError("User missing")
	}

	if *password == "" {
		return setError("Passwords missing")
	}

	if *password != *cpassword {
		return setError("Password and Confirm password not matching")
	}

	cmd := exec.Command("passwd", *user)

	// Get a pipe to write to the command's standard input
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return setError(err.Error())
	}

	// Write password twice (for confirmation)
	go func() {
		defer stdin.Close()
		io.WriteString(stdin, *password+"\n")
		io.WriteString(stdin, *cpassword+"\n")
	}()

	var output bytes.Buffer
	cmd.Stdout = &output

	var cmdErr string
	if err := cmd.Run(); err != nil {
		cmdErr = err.Error()
	}

	return map[string]any{
		"output":    output.String(),
		"exit_code": cmd.ProcessState.ExitCode(),
		"error":     cmdErr,
	}
}

func Useradd(userData *models.User, args *[]string) map[string]any {
	var output bytes.Buffer
	var stderr bytes.Buffer

	cmd := exec.Command("useradd", *args...)
	cmd.Stderr = &stderr // Capture errors
	cmd.Stdout = &output

	err := cmd.Run()
	resp := map[string]any{
		"msg":       "User created",
		"exit_code": cmd.ProcessState.ExitCode(),
	}

	if err != nil {
		resp["error"] = err.Error()
		resp["msg"] = stderr.String()
		return resp
	}

	// Look up the user in OS
	userObj, _ := user.Lookup(userData.User)

	userData.HomeDir = userObj.HomeDir
	userData.Uid, _ = strconv.Atoi(userObj.Uid)
	userData.Gid, _ = strconv.Atoi(userObj.Gid)

	// Get db client
	dbClient, _ := db.GetDB()

	// Delete the user from db if exists
	models.DeleteUsers(dbClient, &[]string{userData.User})

	// Save user in db
	resp["dboutput"], resp["dberror"] = models.SaveUser(dbClient, *userData)

	resp["output"] = output.String()
	return resp
}
