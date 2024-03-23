package main

import (
	"fabric-did/controller"
	"github.com/gin-gonic/gin"
)

func main() {

	r := gin.Default()
	r.Static("/static", "./static")
	//加载api
	//路由分组contract
	contractRouter := r.Group("/api")
	contractRouter.Use(controller.CorsInterceptor())
	contractRouter.POST("/genKeys", controller.GenKeys)
	contractRouter.POST("/registerDID", controller.RegisterDID)
	contractRouter.GET("/searchVC", controller.SearchVC)
	contractRouter.POST("/createVC", controller.CreateVC)
	contractRouter.GET("/genQrcode", controller.GenQrcode)
	contractRouter.GET("/genQrcodeBase64", controller.GenQrcodeBase64)
	contractRouter.POST("/login", controller.Login)
	contractRouter.POST("/loginCheck", controller.LoginCheck)
	contractRouter.POST("/sign", controller.Sign)
	contractRouter.POST("/createPersonCommit", controller.CreatePersonCommit)
	contractRouter.POST("/issue", controller.Issue)
	contractRouter.GET("/searchLatestVC", controller.SearchLatestVC)

	//默认8080端口
	err := r.Run("0.0.0.0:8080")
	if err != nil {
		return
	}
}
