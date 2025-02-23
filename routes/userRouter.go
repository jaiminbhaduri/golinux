package routes

import (
	"github.com/jaiminbhaduri/golinux/controllers"
	"github.com/jaiminbhaduri/golinux/middleware"

	"github.com/gin-gonic/gin"
)

func UserRoutes(router *gin.Engine) {
	router.POST("/user/rebuild_users_db", controllers.RebuildUserdb())
	router.POST("/user/login", middleware.CheckUserInOS(), middleware.CheckUserInDB(), controllers.Login())

	user := router.Group("/user", middleware.AuthMiddleware(), middleware.CheckUserInOS(), middleware.CheckUserInDB(), middleware.CheckUserInLogins())
	{
		user.POST("/logout", controllers.Logout())

		// Only root user allowed to access below APIs
		root := user.Group("/", middleware.IsRoot())
		{
			root.GET("/listuser", controllers.Listusers())
			root.POST("/adduser", controllers.Adduser())
			root.DELETE("/deluser", controllers.Delusers())
			root.GET("/userlogins", controllers.Userlogins())
			//root.PUT("/changeUserPasswd", controllers.SetUserPasswd())
		}
	}
}
