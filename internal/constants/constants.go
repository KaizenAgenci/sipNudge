package constants

import "time"

// auth constants
const (
	// Access tokens expire in 1 hour.
    AccessTokenExpiry = time.Hour * 1
    // Refresh tokens expire in 30 days.
    RefreshTokenExpiry = 30 * 24 * time.Hour
)

const (
	Email  string = "email"
	Expiry string = "expiry"
)

const (
	JwtSecret  string = "JWT_SECRET"
	DbName     string = "DB_NAME"
	DbUser     string = "DB_USER"
	DbPassword string = "DB_PASSWORD"
	DbHost     string = "DB_HOST"
	DbPort     string = "DB_PORT"
)
