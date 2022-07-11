package main

import (
	"golang-sample-jwt/config"
	"golang-sample-jwt/delivery/middleware"
	"golang-sample-jwt/model"
	"golang-sample-jwt/utils"
	"net/http"

	"github.com/gin-gonic/gin"
)

type AuthHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

func main() {
	routerEngine := gin.Default()
	// routerEngine.Use(AuthTokenMiddleware()) // ini global

	cfg := config.NewConfig()
	tokenService := utils.NewTokenService(cfg.TokenConfig)

	routerGroup := routerEngine.Group("/api")

	// LOGIN
	routerGroup.POST("/auth/login", func(ctx *gin.Context) {
		var user model.Credential
		if err := ctx.BindJSON(&user); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"message": "can't find struct",
			})
			return
		}
		if user.Username == "enigma" && user.Password == "123" {
			token, err := tokenService.CreateAccessToken(&user)
			if err != nil {
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			err = tokenService.StoreAccessToken(user.Username, token)
			if err != nil {
				ctx.AbortWithStatus(http.StatusUnauthorized)
				return
			}
			ctx.JSON(200, gin.H{
				"token": token,
			})
		} else {
			ctx.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	// GET CUSTOMER
	protectedGroup := routerGroup.Group("/master", middleware.NewTokenValidator(tokenService).RequireToken())
	protectedGroup.GET("/customer", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.GetString("user-id"),
		})

	})

	protectedGroup.GET("/product", func(ctx *gin.Context) {
		ctx.JSON(http.StatusOK, gin.H{
			"message": ctx.GetString("user-id"),
		})

	})

	err := routerEngine.Run("localhost:8080")
	if err != nil {
		panic(err)
	}
}
