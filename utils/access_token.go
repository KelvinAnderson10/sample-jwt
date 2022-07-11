package utils

import (
	"fmt"
	"golang-sample-jwt/config"
	"golang-sample-jwt/model"
	"log"
	"time"

	"github.com/golang-jwt/jwt"
)

type Token interface {
	CreateAccessToken(cred *model.Credential) (string, error)
	VerifyAccessToken(tokenString string) (jwt.MapClaims, error)
}

type token struct {
	cfg config.TokenConfig
}

func (t *token) CreateAccessToken(cred *model.Credential) (string, error) {
	now := time.Now().UTC()
	end := now.Add(t.cfg.AccessTokenLifeTime)
	claims := MyClaims{
		StandardClaims: jwt.StandardClaims{
			Issuer:    t.cfg.ApplicationName,
			IssuedAt:  now.Unix(),
			ExpiresAt: end.Unix(),
		},
		Username: cred.Username,
		Email:    cred.Email,
	}

	token := jwt.NewWithClaims(t.cfg.JwtSigningMethod, claims)
	return token.SignedString([]byte(t.cfg.JwtSignatureKey))
}

func (t *token) VerifyAccessToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if method, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("signing method invalid")
		} else if method != t.cfg.JwtSigningMethod {
			return nil, fmt.Errorf("signing method invalid")
		}

		return []byte(t.cfg.JwtSignatureKey), nil
	})
	if err != nil {
		log.Println(err.Error())
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid || claims["iss"] != t.cfg.ApplicationName {
		log.Println("Token invalid...")
		return nil, err
	}
	return claims, nil
}

func NewTokenService(cfg config.TokenConfig) Token {
	newToken := new(token)
	newToken.cfg = cfg
	return newToken
}
