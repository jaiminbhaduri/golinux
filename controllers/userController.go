package controllers

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"os/exec"
	osuser "os/user"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jaiminbhaduri/golinux/config"
	"github.com/jaiminbhaduri/golinux/db"
	"github.com/jaiminbhaduri/golinux/helpers"
	"github.com/jaiminbhaduri/golinux/models"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/gin-gonic/gin"
)

func RebuildUserdb() gin.HandlerFunc {
	return func(c *gin.Context) {
		response := make(map[string]any)

		// Rebuild the users db
		output, err := models.Rebuild_users_db()
		response["dboutput"] = output
		response["dberror"] = err

		c.JSON(http.StatusOK, gin.H{"msg": "Done", "response": response})
	}
}

type LoginStruct struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body LoginStruct

		// Bind JSON payload to struct
		if err := c.BindJSON(&body); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid json format", "error": err.Error()})
			return
		}

		userdocRaw, _ := c.Get("userdoc")
		userdoc, _ := userdocRaw.(models.User)

		// System users cannot login (Root user can login)
		if slices.Contains(config.ReservedUsers, userdoc.User) || (userdoc.Uid != 0 && userdoc.Uid < 1000) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Reserved user"})
			return
		}

		// Check if password is correct
		ok, err := helpers.VerifyPassword(userdoc.User, body.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Password incorrect"})
			return
		}

		login_duration_str := os.Getenv("MAX_LOGIN_DURATION")
		login_duration, _ := strconv.Atoi(login_duration_str)

		currtime := time.Now().UTC()
		exptime := time.Now().UTC().Add(time.Duration(login_duration) * time.Hour)

		login := models.LoginStruct{
			User:      userdoc.User,
			Userid:    userdoc.ID.Hex(),
			UserAgent: c.GetHeader("User-Agent"),
			Mac:       helpers.GetMacAddress(),
			Ip:        helpers.GetIPAddress(c),
			LoginAt:   currtime,
			Exptime:   exptime,
		}

		db, _ := db.GetDB()
		dboutput, dberr := models.SaveLogin(db, &login)
		if dberr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": "Login db error", "error": dberr.Error()})
			return
		}

		insertedLoginId, _ := dboutput.InsertedID.(bson.ObjectID)
		insertedId := insertedLoginId.Hex()

		// Generate jwt
		token, tokenErr := helpers.GenerateToken(userdoc.ID.Hex(), insertedId, userdoc.User, currtime, exptime)
		if tokenErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "msg": "token creation error"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"msg": "Login success", "data": token, "dboutput": dboutput, "dberror": dberr})
	}
}

func Logout() gin.HandlerFunc {
	return func(c *gin.Context) {
		logindocRaw, _ := c.Get("logindoc")
		logindoc, _ := logindocRaw.(bson.M)

		db, _ := db.GetDB()
		output, _ := models.LogoutDeletion(db, logindoc)

		c.JSON(http.StatusOK, gin.H{"msg": "Logout successful", "dboutput": output})
	}
}

func Listusers() gin.HandlerFunc {
	return func(c *gin.Context) {
		db, _ := db.GetDB()
		collection := db.Collection("users")
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()

		// Parse limit and page with default values
		//limitStr := c.DefaultQuery("limit", "")
		//pageStr := c.DefaultQuery("page", "")

		// Count total users in the collection
		totalUsers, err := collection.CountDocuments(ctx, bson.M{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count users"})
			return
		}

		cursor, err := collection.Find(ctx, bson.M{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Unpack the cursor into a slice
		var results []any
		if err = cursor.All(ctx, &results); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Response JSON with pagination metadata
		c.JSON(http.StatusOK, gin.H{
			"total_users": totalUsers,
			//"limit":       limit,
			//"page":        page,
			"data": results,
		})
	}
}

type AddUserStruct struct {
	User      string `json:"user"`
	HomeDir   string `json:"home"`
	Password  string `json:"password"`
	Cpassword string `json:"cpassword"`
	Shell     string `json:"shell"`
	Comment   string `json:"comment"`
	//Expiry     time.Time `json:"expiry"`
	SystemUser bool `json:"system_user"`
	Uid        int  `json:"uid"`
}

func Adduser() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body AddUserStruct

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

		shells, err := helpers.GetShells()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"msg": "error fetching shells", "error": err.Error()})
			return
		}

		args := []string{body.User}

		if body.Shell != "" && slices.Contains(shells, body.Shell) {
			args = append(args, "-s", body.Shell)
		}

		if body.Comment != "" {
			args = append(args, "-c", body.Comment)
		}

		if body.HomeDir != "" {
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

		resp := make(map[string]any)

		userData := models.User{
			User:       body.User,
			Shell:      body.Shell,
			Comment:    body.Comment,
			SystemUser: body.SystemUser,
		}

		// Linux user creation response
		resp["user_creation"] = helpers.Useradd(&userData, &args)

		if userCreation, ok := resp["user_creation"].(map[string]any); ok {
			if _, exists := userCreation["error"]; !exists && body.Password != "" && body.Cpassword != "" {
				// Linux user password setting response
				resp["passwd"] = helpers.SetUserPasswd(&body.User, &body.Password, &body.Cpassword)
			}
		}

		c.JSON(http.StatusOK, resp)
	}
}

type DelUsersStruct struct {
	Users      []string `json:"users"`
	RemoveHome bool     `json:"remove_home"`
}

// Delete linux user/s
func Delusers() gin.HandlerFunc {
	return func(c *gin.Context) {
		var body DelUsersStruct

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

		var usersToDelete []string

		for _, user := range body.Users {
			user = strings.TrimSpace(user)
			userObj, _ := osuser.Lookup(user)
			if userObj != nil {
				uid, _ := strconv.Atoi(userObj.Uid)

				// Restrict System users deletion
				if slices.Contains(config.ReservedUsers, user) || uid < 1000 {
					continue
				}
			}

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

			// 0 for successful deletion, 6 for user not found in OS
			if exitCode == 0 || exitCode == 6 {
				usersToDelete = append(usersToDelete, user)
			}

			response[user] = userData
		}

		// Get db client
		dbClient, _ := db.GetDB()

		// Delete the users from db
		output, delErr := models.DeleteUsers(dbClient, &usersToDelete)
		response["dboutput"] = output
		response["dberror"] = delErr

		c.JSON(http.StatusOK, gin.H{"msg": "Done", "response": response})
	}
}

func Userlogins() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()
		db, _ := db.GetDB()
		cursor, err := db.Collection("logins").Find(ctx, bson.M{})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Unpacks the cursor into a slice
		var results []any
		if err = cursor.All(ctx, &results); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": results})
	}
}

func Accesslogs() gin.HandlerFunc {
	return func(c *gin.Context) {
		data, err := os.ReadFile("/var/log/golinux/access.log")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"msg": "Failed to read log file", "error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": data})
	}
}
