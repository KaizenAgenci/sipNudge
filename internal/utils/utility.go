package utils

import (
	"errors"
	"fmt"
	"os"
	"time"

	"sipNudge/internal/constants"

	"github.com/golang-jwt/jwt/v4"
)

// GenerateTokens generates a JWT token for the provided email.
func GenerateTokens(email string) (string, error) {
	// Define token claims including the email.
	claims := jwt.MapClaims{
		"email": email,                                        // email is added as a claim
		"exp":   time.Now().Add(constants.AccessTokenExpiry).Unix(), // expiration time
		"iat":   time.Now().Unix(),                            // issued at
	}

	// Create a new token with the claims.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Get the JWT secret from environment variables.
	jwtSecret := os.Getenv(constants.JwtSecret)
	if jwtSecret == "" {
		return "", errors.New("JWT secret not set in environment variables")
	}

	// Sign the token using the secret converted to a byte slice.
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", fmt.Errorf("error signing token: %w", err)
	}

	return tokenString, nil
}


func GenerateRefreshToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(constants.RefreshTokenExpiry).Unix(), // refresh token expiry
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := os.Getenv(constants.JwtSecret)
	if jwtSecret == "" {
		return "", errors.New("JWT secret not set in environment variables")
	}
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", fmt.Errorf("error signing refresh token: %w", err)
	}
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
