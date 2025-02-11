package controllers

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/jaiminbhaduri/golinux/config"
	"github.com/jaiminbhaduri/golinux/helpers"

	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body LoginRequest

		// Bind JSON payload to struct
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid json format", "error": err.Error()})
			return
		}

		// Trim the whitespaces from username
		username := strings.Trim(body.Username, " ")

		// User input validation
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, username); !matched {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Username format"})
			return
		}

		// Check if user exists in linux system
		userObj, err := user.Lookup(username)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
			return
		}

		// Convert uid & gid from string to integer
		uid, _ := strconv.Atoi(userObj.Uid)
		//gid, _ := strconv.Atoi(userObj.Gid)

		// System users cannot login
		if slices.Contains(config.ReservedUsers, username) || (uid != 0 && uid < 1000) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Reserved user"})
			return
		}

		// Check if password is correct
		ok, err := helpers.VerifyPassword(body.Username, body.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Password incorrect"})
			return
		}

		// Set UID and GID
		// if err := syscall.Setgid(gid); err != nil {
		// 	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		// 	return
		// }

		// if err := syscall.Setuid(uid); err != nil {
		// 	c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		// 	return
		// }

		c.JSON(http.StatusOK, gin.H{"msg": "Login success", "data": userObj})
	}
}

func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("logout")
	}
}

func Listuser() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Parse limit and page with default values
		limit, err := strconv.Atoi(c.DefaultQuery("limit", "10"))
		if err != nil || limit <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid limit value"})
			return
		}

		page, err := strconv.Atoi(c.DefaultQuery("page", "1"))
		if err != nil || page <= 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid page value"})
			return
		}

		// Open and read /etc/passwd efficiently
		data, err := os.ReadFile("/etc/passwd")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": "Failed to read system users", "error": err})
			return
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		totalUsers := len(lines)
		if totalUsers == 0 {
			c.JSON(http.StatusOK, gin.H{"msg": "No users found"})
			return
		}

		// Compute pagination indices
		startIndex := (page - 1) * limit
		if startIndex >= totalUsers {
			c.JSON(http.StatusOK, gin.H{"msg": "No more users"})
			return
		}

		endIndex := startIndex + limit
		if endIndex > totalUsers {
			endIndex = totalUsers
		}

		// Extract and format users
		users := make([][]string, 0, endIndex-startIndex)
		for _, line := range lines[startIndex:endIndex] {
			slice := strings.Split(line, ":")
			slice = append(slice[:1], slice[2:]...) // Extract relevant fields
			users = append(users, slice)
		}

		// Return paginated result
		c.JSON(http.StatusOK, gin.H{
			"data":  users,
			"page":  page,
			"limit": limit,
			"total": totalUsers,
		})
	}
}

type AddUserBody struct {
	User      string `json:"user"`
	HomeDir   string `json:"home"`
	Password  string `json:"password"`
	Cpassword string `json:"cpassword"`
	Shell     string `json:"shell"`
	Comment   string `json:"comment"`
	//Expiry     time.Time `json:"expiry"`
	NoLogInit  bool `json:"no_log_init"`
	NoHome     bool `json:"no_home"`
	SystemUser bool `json:"system_user"`
	Uid        int  `json:"uid"`
}

func Adduser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body AddUserBody

		// Bind JSON payload to struct
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid json format", "error": err.Error()})
			return
		}

		if body.Password != body.Cpassword {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password and Confirm Password does not match"})
			return
		}

		// sudoUsers, err := helpers.GetSudoUsers()
		// if err != nil {
		// 	c.JSON(http.StatusBadRequest, gin.H{"msg": "error fetching sudo users", "error": err.Error()})
		// 	return
		// }

		//shells, err := helpers.GetShells()

		args := []string{body.User, "-s", body.Shell}

		if body.Comment != "" {
			args = append(args, "-c", body.Comment)
		}

		if body.NoHome {
			args = append(args, "-M")
		} else if body.HomeDir != "" {
			args = append(args, "-d", body.HomeDir)
		} else {
			args = append(args, "-m")
		}

		if body.Uid > 0 {
			args = append(args, "-u", strconv.Itoa(body.Uid))
		}

		if body.SystemUser {
			args = append(args, "-r")
		}

		if body.NoLogInit {
			args = append(args, "-l")
		}

		var output bytes.Buffer
		var stderr bytes.Buffer

		cmd := exec.Command("useradd", args...)
		cmd.Stderr = &stderr // Capture errors
		cmd.Stdout = &output

		if err := cmd.Run(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "exit_code": cmd.ProcessState.ExitCode(), "msg": stderr.String()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"msg": "User created", "exit_code": cmd.ProcessState.ExitCode(), "output": output.String()})
	}
}

type DelUsers struct {
	Users      []string `json:"users"`
	RemoveHome bool     `json:"remove_home"`
}

// Delete a linux user
func Delusers() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body DelUsers

		// Bind JSON payload to struct
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid json format", "error": err.Error()})
			return
		}

		if len(body.Users) == 0 {
			c.JSON(400, gin.H{"error": "no users provided"})
			return
		}

		var args []string
		if body.RemoveHome {
			args = append(args, "-r")
		}

		response := make(map[string]any)

		for _, user := range body.Users {
			cmdArgs := append(args, user)

			cmd := exec.Command("userdel", cmdArgs...)

			var output bytes.Buffer
			var stderr bytes.Buffer
			cmd.Stdout = &output
			cmd.Stderr = &stderr

			err := cmd.Run()
			exitCode := cmd.ProcessState.ExitCode() // Get the exit code

			userData := map[string]interface{}{
				"exit_code": exitCode,
				"output":    output.String(),
				"error":     stderr.String(),
				"status":    "success",
			}

			if err != nil {
				userData["status"] = "failed"
			}

			response[user] = userData
		}

		c.JSON(http.StatusOK, gin.H{"msg": "Done", "response": response})
	}
}
