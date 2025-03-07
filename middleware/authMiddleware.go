package middleware

import (
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// JWT Claims structure
type ClaimsStruct struct {
	User    string `json:"user"`
	Loginid string `json:"loginid"`
	Userid  string `json:"userid"`
	jwt.RegisteredClaims
}

// AuthMiddleware extracts JWT from the request and adds user details to the context
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		secretkey := os.Getenv("SECRET_KEY")
		jwtSecret := []byte(secretkey)

		// Get Authorization header
		bearerToken := c.GetHeader("Authorization")
		if bearerToken == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
			c.Abort()
			return
		}

		// Extract token (remove "Bearer ")
		tokenString := strings.TrimPrefix(bearerToken, "Bearer ")

		// Parse token
		claims := &ClaimsStruct{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtSecret, nil
		})

		// Handle invalid token
		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"msg": "Invalid token", "error": err.Error()})
			c.Abort()
			return
		}

		// Add extracted data to the request context
		c.Set("claims", claims)
		c.Set("user", claims.User)
		c.Set("loginid", claims.Loginid)
		c.Set("userid", claims.Userid)

		// Continue to the next handler
		c.Next()
	}
}
