package middleware

import (
	"fmt"
	"golang-sample-jwt/utils"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type AuthTokenMiddleware interface {
	RequireToken() gin.HandlerFunc
}

type authTokenMiddleware struct {
	accToken utils.Token
}

type authHeader struct {
	AuthorizationHeader string `header:"Authorization"`
}

func (a *authTokenMiddleware) RequireToken() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		h := authHeader{}
		if err := ctx.ShouldBindHeader(&h); err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message": "Unauthorized",
			})
			ctx.Abort()
			return
		}

		tokenString := strings.Replace(h.AuthorizationHeader, "Bearer ", "", -1)
		fmt.Println("token string: ", tokenString)
		if tokenString == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"nessage": "token invalid",
			})
			ctx.Abort()
			return
		}
		token, err := a.accToken.VerifyAccessToken(tokenString)
		userId, err := a.accToken.FetchAccessToken(token)
		if userId == "" || err != nil {
			// Kalau token salah
			fmt.Println(err)
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"message error parse": "Unauthorized",
			})
			ctx.Abort()
			return
		}
		fmt.Println("token ", token)
		if token != nil {
			ctx.Set("user-id", userId)
			ctx.Next()
		} else {
			ctx.JSON(http.StatusUnauthorized, gin.H{
				"nessage": "Unauthorized",
			})
			ctx.Abort()
			return
		}
	}
}

func NewTokenValidator(accToken utils.Token) AuthTokenMiddleware {
	return &authTokenMiddleware{accToken: accToken}
}
