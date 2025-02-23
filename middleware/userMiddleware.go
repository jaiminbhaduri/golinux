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

	"github.com/gin-gonic/gin"
	"github.com/jaiminbhaduri/golinux/db"
	"go.mongodb.org/mongo-driver/bson"
)

func CheckUserInOS() gin.HandlerFunc {
	return func(c *gin.Context) {
		var bodyData map[string]interface{}

		// Try to read the body
		body, err := io.ReadAll(c.Request.Body)
		if err == nil && len(body) > 0 {
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

		claims := &ClaimsStruct{}

		// Check if user is stored in the context (e.g., from JWT)
		if user == "" {
			if claimsRaw, exists := c.Get("claims"); exists {
				claims, _ = claimsRaw.(*ClaimsStruct)
				user = claims.User
			}
		}

		if user == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid user", "msg": "User missing on lookup"})
			c.Abort()
			return
		}

		// Trim the whitespaces from username
		user = strings.Trim(user, " ")

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
		c.Set("claims", claims)
		c.Next()
	}
}

func CheckUserInDB() gin.HandlerFunc {
	return func(c *gin.Context) {
		userObjRaw, _ := c.Get("userObj")
		userObj, _ := userObjRaw.(*osuser.User)

		claimsRaw, _ := c.Get("claims")
		claims, _ := claimsRaw.(*ClaimsStruct)

		var filter bson.M
		if claims.User == "" {
			filter = bson.M{"user": userObj.Username}
		} else {
			filter = bson.M{"user": claims.User, "uuid": claims.Uuid}
		}

		// Get db client
		db, _ := db.GetDB()

		var result bson.M

		// Retrieve the user's document from db
		doc := db.Collection("users").FindOne(context.TODO(), filter)

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
		filter := bson.M{"user": claims.User, "uuid": claims.Uuid, "loginuid": claims.LoginUid}
		var result bson.M

		// Get db client
		db, _ := db.GetDB()

		// Check if user exists in logins table
		doc := db.Collection("logins").FindOne(context.TODO(), filter)
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
		userdocRaw, _ := c.Get("userdoc")
		userdoc, _ := userdocRaw.(bson.M)
		user, _ := userdoc["user"].(string)

		if user != "root" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Only root user allowed to do this operation"})
			c.Abort()
			return
		}

		c.Next()
	}
}
