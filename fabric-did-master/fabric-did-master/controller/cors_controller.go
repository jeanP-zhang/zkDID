package controller

import "github.com/gin-gonic/gin"

// http 请求拦截器
func CorsInterceptor() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 执行下一个
		c.Next()
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "POST, GET, OPTIONS, DELETE, PUT")
		c.Header("Access-Control-Max-Age", "3600")
	}
}
