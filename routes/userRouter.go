package routes

import (
	"github.com/jaiminbhaduri/golinux/controllers"

	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	router.POST("/user/login", controllers.Login())

	user := router.Group("/user")
	{
		user.POST("/logout", controllers.Logout())
		user.GET("/listuser", controllers.Listuser())
		user.POST("/adduser", controllers.Adduser())
		user.DELETE("/deluser", controllers.Delusers())
		//user.PUT("/changeUserPasswd", controllers.SetUserPasswd())
	}
}
