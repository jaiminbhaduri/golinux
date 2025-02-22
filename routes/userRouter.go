package routes

import (
	"github.com/jaiminbhaduri/golinux/controllers"
	"github.com/jaiminbhaduri/golinux/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	router.POST("/user/login", controllers.Login())

	user := router.Group("/user", middleware.AuthMiddleware(), middleware.CheckUserExists())
	{
		user.POST("/logout", controllers.Logout())
		user.GET("/listuser", controllers.Listuser())
		user.POST("/adduser", controllers.Adduser())
		user.DELETE("/deluser", controllers.Delusers())
		user.POST("/rebuild_users_db", controllers.RebuildUserdb())
		//user.PUT("/changeUserPasswd", controllers.SetUserPasswd())
	}
}
