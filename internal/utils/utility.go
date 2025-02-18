package utils

import (
	"errors"
	"os"
	"sipNudge/internal/Constants"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Generate Tokens
func GenerateTokens(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		Constants.Email:  email,
		Constants.Expiry: time.Now().Add(Constants.TokenExpiry).Unix(),
	})

	jwtSecret := os.Getenv(Constants.JwtSecret)

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", errors.New("error occured at token signed string")
	}
	//TODO store token in DB

	return tokenString, nil
}

// // Generate Access and Refresh Tokens
// func generateTokens(email string) (string, string, error) {
// 	// Create Access Token
// 	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"email": email,
// 		"exp":   time.Now().Add(accessTokenExpiry).Unix(),
// 	})
// 	accessTokenString, err := accessToken.SignedString(jwtSecret)
// 	if err != nil {
// 		return "", "", err
// 	}
//
// 	// Create Refresh Token
// 	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
// 		"email": email,
// 		"exp":   time.Now().Add(refreshTokenExpiry).Unix(),
// 	})
// 	refreshTokenString, err := refreshToken.SignedString(refreshSecret)
// 	if err != nil {
// 		return "", "", err
// 	}
//
// 	// Store refresh token
// 	refreshTokens[refreshTokenString] = email
//
// 	return accessTokenString, refreshTokenString, nil
// }
//
