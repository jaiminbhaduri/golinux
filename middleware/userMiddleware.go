package middleware

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	osuser "os/user"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaiminbhaduri/golinux/db"
	"github.com/jaiminbhaduri/golinux/models"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// Check user in OS and DB before login
func CheckUserExists() gin.HandlerFunc {
	return func(c *gin.Context) {
		var bodyData map[string]interface{}

		// Try to read the body
		body, readerr := io.ReadAll(c.Request.Body)
		if readerr == nil && len(body) > 0 {
			// Parse JSON body into a map
			if err := json.Unmarshal(body, &bodyData); err == nil {
				// Store the body in the context
				c.Set("request_body", bodyData)
			}
			// Restore body so handlers can read it later
			c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
		}

		// Try to get user from body
		var user string
		if bodyData != nil {
			if val, ok := bodyData["username"].(string); ok {
				user = val
			}
		}

		// Trim the whitespaces from username
		user = strings.Trim(user, " ")

		if user == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user", "msg": "User missing on lookup"})
			c.Abort()
			return
		}

		// User input validation
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, user); !matched {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Username format"})
			c.Abort()
			return
		}

		// Check if user exists in linux system
		userObj, oserr := osuser.Lookup(user)
		if oserr != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": oserr.Error(), "msg": "Error while user lookup in OS"})
			c.Abort()
			return
		}

		// Get db client
		db, _ := db.GetDB()
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()
		var result models.User

		// Retrieve the user's document from db
		doc := db.Collection("users").FindOne(ctx, bson.M{"user": userObj.Username})

		// Decode the document
		if err := doc.Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "msg": "Error on user lookup in db"})
			c.Abort()
			return
		}

		c.Set("userdoc", result)
		c.Set("userObj", userObj)
		c.Next()
	}
}

func CheckUserInOS() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims := &ClaimsStruct{}
		var user string

		if claimsRaw, exists := c.Get("claims"); exists {
			claims, _ = claimsRaw.(*ClaimsStruct)
			user = claims.User
		}

		// Trim the whitespaces from username
		user = strings.Trim(user, " ")

		if user == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user", "msg": "User missing on lookup"})
			c.Abort()
			return
		}

		// User input validation
		if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_-]+$`, user); !matched {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Username format"})
			c.Abort()
			return
		}

		// Check if user exists in linux system
		userObj, err := osuser.Lookup(user)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": err.Error(), "msg": "Error while user lookup in OS"})
			c.Abort()
			return
		}

		c.Set("userObj", userObj)
		c.Next()
	}
}

func CheckUserInDB() gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsRaw, _ := c.Get("claims")
		claims, _ := claimsRaw.(*ClaimsStruct)
		userOid, oidErr := bson.ObjectIDFromHex(claims.Userid)
		if oidErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": oidErr.Error(), "msg": "Object id parse error"})
			c.Abort()
			return
		}

		// Get db client
		db, _ := db.GetDB()
		ctx, cancel := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancel()
		filter := bson.M{"user": claims.User, "_id": userOid}
		var result models.User

		// Retrieve the user's document from db
		doc := db.Collection("users").FindOne(ctx, filter)

		// Decode the document
		if err := doc.Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "msg": "Error on user lookup in db"})
			c.Abort()
			return
		}

		c.Set("userdoc", result)
		c.Next()
	}
}

func CheckUserInLogins() gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsRaw, _ := c.Get("claims")
		claims, _ := claimsRaw.(*ClaimsStruct)
		loginOid, err := bson.ObjectIDFromHex(claims.Loginid)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "msg": "login object id error"})
			c.Abort()
			return
		}

		filter := bson.M{"user": claims.User, "userid": claims.Userid, "_id": loginOid}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		var result *models.LoginStruct

		// Get db client
		db, _ := db.GetDB()

		// Check if user exists in logins table
		doc := db.Collection("logins").FindOne(ctx, filter)
		doc.Decode(&result)

		if result == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not logged in", "msg": "User missing in logins"})
			c.Abort()
			return
		}

		c.Set("logindoc", result)
		c.Next()
	}
}

func IsRoot() gin.HandlerFunc {
	return func(c *gin.Context) {
		user, ok := c.Get("user")
		if !ok {
			c.JSON(http.StatusNotFound, gin.H{"error": "User missing"})
			c.Abort()
			return
		}

		if user != "root" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Only root user allowed to do this operation"})
			c.Abort()
			return
		}

		c.Next()
	}
}
