package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jaiminbhaduri/golinux/db"
	"go.mongodb.org/mongo-driver/bson"
)

func CheckUserExists() gin.HandlerFunc {
	return func(c *gin.Context) {
		claimsRaw, _ := c.Get("claims")
		claims, _ := claimsRaw.(*Claims)

		// Get db client
		db, _ := db.GetDB()

		filter := bson.M{"user": claims.User, "uid": claims.Uid, "uuid": claims.Uuid}
		var result bson.M

		// Retrieve the user's document from db
		doc := db.Collection("users").FindOne(context.TODO(), filter)

		// Decode the document
		if err := doc.Decode(&result); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error(), "msg": "Problem finding record in db"})
			c.Abort()
			return
		}

		c.Set("userinfo", result)

		c.Next()
	}
}
