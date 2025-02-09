package middleware

// ErrorLoggerMiddleware logs all errors to /var/log/golinux/error.log
// func Errorlogs() gin.HandlerFunc {
// 	// Open the error log file (append mode)
// 	file, err := os.OpenFile("/var/log/golinux/error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
// 	if err != nil {
// 		log.Fatalf("Failed to open error log file: %v", err)
// 	}

// 	// Create a logger
// 	logger := log.New(file, "", log.LstdFlags)

// 	return func(c *gin.Context) {
// 		// Process the request
// 		c.Next()

// 		// Check if there are any errors
// 		for _, err := range c.Errors {
// 			logger.Printf("[%s] %s %s | ERROR: %v\n",
// 				time.Now().Format("2006-01-02 15:04:05"),
// 				c.Request.Method,
// 				c.Request.URL.Path,
// 				err.Err,
// 			)
// 		}
// 	}
// }
