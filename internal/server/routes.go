package server

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	Constants "sipNudge/internal/constants"
	"sipNudge/internal/models"
	"sipNudge/internal/utils"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

// RegisterRoutes initializes all server routes
func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", s.healthHandler)
	r.Get("/api/v1/status", s.statusHandler) // New API to check server status
	r.Post("/api/v1/signIn", s.handleSignIn)
	r.Post("/api/v1/signUp", s.handleSignUp)
	r.Post("/api/v1/refreshToken", s.handleRefreshToken)
	r.Get("/api/v1/users", s.handleFetchUsers)
	return r
}

// Health check endpoint
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	if err := s.db.CheckConnection(); err != nil {
		http.Error(w, "Database connection failed", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusAccepted)
	w.Write([]byte(`{"message": "Accepted"}`))
}

// Server status endpoint
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "Server working correctly"})
}

// Sign-in logic
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var req models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var hashedPassword string
	err := s.db.QueryRow("SELECT password_hash FROM Users WHERE email = ?", req.Email).Scan(&hashedPassword)
	if err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)) != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	// Generate JWT token
	token, err := utils.GenerateTokens(req.Email)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(models.AuthResponse{
		Token: token,
	})
}

// Sign-up logic
func (s *Server) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var req models.AuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var exists int
	err := s.db.QueryRow("SELECT COUNT(*) FROM Users WHERE email = ?", req.Email).Scan(&exists)
	if err != nil || exists > 0 {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	// Hash password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	_, err = s.db.Exec("INSERT INTO Users (email, password_hash) VALUES (?, ?)", req.Email, hashedPassword)
	if err != nil {
		http.Error(w, "Failed to create user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered successfully"})
}

// Refresh token logic
func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	var req models.RefreshTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	jwtSecret := []byte(os.Getenv(Constants.DbName)) // Using database env for security
	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"message": "Token refreshed"})

	//Extract Email from token
	// claims, _ := token.Claims.(jwt.MapClaims)

	//TODO 1. validate token from db
	// 2. Generate new tokens (ROTATE tokens)
	// 3. Remove old Tokens and store new ones in the db
	// 4. return the new token as repsonse

}

// Fetch users with optional email filter
func (s *Server) handleFetchUsers(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email") // Get email from query parameters

	query := "SELECT id, email, has_biometrics, COALESCE(device_token, ''), is_blocked, failed_attempts FROM Users"
	var rows *sql.Rows
	var err error

	if email != "" {
		query += " WHERE email = ?"
		rows, err = s.db.Query(query, email)
	} else {
		rows, err = s.db.Query(query)
	}
	if err != nil {
		http.Error(w, "Failed to fetch users: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []models.User

	for rows.Next() {
		var user models.User

		err := rows.Scan(
			&user.ID,
			&user.Email,
			&user.HasBiometrics,
			&user.DeviceToken,
			&user.IsBlocked,
			&user.FailedAttempts,
		)
		if err != nil {
			http.Error(w, "Error scanning user data: "+err.Error(), http.StatusInternalServerError)
			return
		}

		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users) // Return users in JSON format
}
