package middleware

import (
	"bytes"
	"io"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jaiminbhaduri/golinux/db"
	"github.com/jaiminbhaduri/golinux/models"
)

// Custom API Logger middleware to log API requests to MongoDB
func ApiLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Extract headers
		headers := make(map[string]string)
		for key, values := range c.Request.Header {
			if len(values) > 0 {
				headers[key] = values[0]
			}
		}

		// Read request body (non-destructive)
		bodyBytes, _ := io.ReadAll(c.Request.Body)
		c.Request.Body = io.NopCloser(io.MultiReader(io.NopCloser(bytes.NewBuffer(bodyBytes)))) // Reset Body

		// Prepare log entry
		apiLog := &models.ApiLogStruct{
			Timestamp: time.Now(),
			Method:    c.Request.Method,
			Path:      c.Request.URL.Path,
			IP:        c.ClientIP(),
			UserAgent: c.Request.UserAgent(),
			Headers:   headers,
			Body:      string(bodyBytes),
		}

		dbclient, _ := db.GetDB()
		if _, err := db.SaveApi(dbclient, apiLog); err != nil {
			log.Println("Error while saving api in db:", err.Error())
		}

		// Continue with request
		c.Next()
	}
}
