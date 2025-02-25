package middleware

import (
	"database/sql"
	"net/http"
	"os"
	"strings"

	"sipNudge/internal/constants"

	"github.com/golang-jwt/jwt/v4"
)

// JWTAuthMiddleware validates the JWT access token and ensures it exists in the database.
// It returns a generic error message ("Unauthorized access") for any token-related error.
func JWTAuthMiddleware(db interface {
	QueryRow(query string, args ...interface{}) *sql.Row
}) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, "Unauthorized access", http.StatusUnauthorized)
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				http.Error(w, "Unauthorized access", http.StatusUnauthorized)
				return
			}
			tokenString := parts[1]

			jwtSecret := []byte(os.Getenv(constants.JwtSecret))
			token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
				return jwtSecret, nil
			})
			if err != nil || !token.Valid {
				http.Error(w, "Unauthorized access", http.StatusUnauthorized)
				return
			}

			// Check that the access token exists in the DB (in the access_token column)
			var count int
			err = db.QueryRow("SELECT COUNT(*) FROM UserTokens WHERE access_token = ?", tokenString).Scan(&count)
			if err != nil || count == 0 {
				http.Error(w, "Unauthorized access", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
