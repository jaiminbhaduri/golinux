package controllers

import (
	"fmt"
	"net/http"
	"os"
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
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read system users"})
			return
		}

		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		totalUsers := len(lines)
		if totalUsers == 0 {
			c.JSON(http.StatusOK, gin.H{"data": []string{}, "message": "No users found"})
			return
		}

		// Compute pagination indices
		startIndex := (page - 1) * limit
		if startIndex >= totalUsers {
			c.JSON(http.StatusOK, gin.H{"data": []string{}, "message": "No more users"})
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
	User    string `json:"user"`
	Home    string `json:"home"`
	Shell   int    `json:"shell"`
	Name    string `json:"name"`
	Comment string `json:"comment"`
}

func Adduser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body AddUserBody

		// Bind JSON payload to struct
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid json format", "error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"msg": "User created", "data": body})
	}
}

// Delete a linux user
func Deluser() gin.HandlerFunc {
	return func(c *gin.Context) {
		fmt.Println("deluser")
	}
}
