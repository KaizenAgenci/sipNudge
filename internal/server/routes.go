package server

import (
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	Constants "sipNudge/internal/constants"
	"sipNudge/internal/models"

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
	r.Post("/api/v1/addUserDetails", s.handleAddUserDetails)
	r.Post("/api/v1/refreshToken", s.handleRefreshToken)
	r.Get("/api/v1/userLoginDetails", s.fetchUserLoginDetails)
	r.Get("/api/v1/userDetails", s.fetchUserDetails)
	r.Post("/api/v1/sendOTP", s.sendOTP)
	r.Post("/api/v1/verifyOTP", s.verifyOTP)
	r.Post("/api/v1/resetPassword", s.resetPassword)
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

// General response function
func sendResponse(w http.ResponseWriter, status int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"message": message,
		"data":    data,
	})
}

// Server status endpoint
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]string{"message": "Server working correctly"})
}

// Sign-in logic
func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {
	var req models.AuthRequest

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	var hashedPassword string

	// Fetch password hash from database
	err := s.db.QueryRow("SELECT password_hash FROM Users WHERE email = ?", req.Email).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			sendResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
		} else {
			sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		}
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)); err != nil {
		sendResponse(w, http.StatusUnauthorized, "Invalid credentials", nil)
		return
	}

	// Generate JWT token
	// token, err := utils.GenerateTokens(req.Email)
	// if err != nil {
	// 	sendResponse(w, http.StatusInternalServerError, "Token generation failed", nil)
	// 	return
	// }

	// Successful response
	sendResponse(w, http.StatusOK, "Password verified successfully", models.AuthResponse{Token: "dummyToken"})
}

// Sign-up logic
func (s *Server) handleSignUp(w http.ResponseWriter, r *http.Request) {
	var req models.AuthRequest

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	// Check if user already exists
	var exists int
	err := s.db.QueryRow("SELECT COUNT(*) FROM Users WHERE email = ?", req.Email).Scan(&exists)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}
	if exists > 0 {
		sendResponse(w, http.StatusConflict, "User already exists", nil)
		return
	}

	// Hash password before storing
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Password hashing failed", nil)
		return
	}

	// Insert user into database
	_, err = s.db.Exec("INSERT INTO Users (email, password_hash) VALUES (?, ?)", req.Email, hashedPassword)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Failed to create user", nil)
		return
	}

	// Success response
	sendResponse(w, http.StatusCreated, "User registered successfully", nil)
}

// Add User Details API
// Add User Details API
func (s *Server) handleAddUserDetails(w http.ResponseWriter, r *http.Request) {
	var req models.UserDetailsRequest

	// Decode request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	// Check if user_id exists in Users table
	var exists int
	err := s.db.QueryRow("SELECT COUNT(*) FROM Users WHERE id = ?", req.UserID).Scan(&exists)
	if err != nil {
		log.Println("Error checking user existence:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}
	if exists == 0 {
		sendResponse(w, http.StatusNotFound, "User ID does not exist", nil)
		return
	}

	// Validate ENUM values
	if req.Gender != "M" && req.Gender != "F" && req.Gender != "Other" {
		sendResponse(w, http.StatusBadRequest, "Invalid gender value", nil)
		return
	}
	if req.ActivityLevel != "Low" && req.ActivityLevel != "Moderate" && req.ActivityLevel != "High" {
		sendResponse(w, http.StatusBadRequest, "Invalid activity level", nil)
		return
	}

	// Insert into UserDetails table
	_, err = s.db.Exec(`
		INSERT INTO SPN_UserDetails (user_id, gender, height_cm, weight_kg, age, wakeup_time, bedtime, activity_level)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		req.UserID, req.Gender, req.HeightCM, req.WeightKG, req.Age, req.WakeupTime, req.Bedtime, req.ActivityLevel,
	)
	if err != nil {
		log.Println("SQL Insert Error:", err)
		sendResponse(w, http.StatusInternalServerError, "Failed to insert user details", nil)
		return
	}

	// Success response
	sendResponse(w, http.StatusCreated, "User details added successfully", nil)
}

// Generate a secure random 6-digit OTP
func generateOTP() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		log.Println("Error generating OTP:", err)
		return ""
	}
	return fmt.Sprintf("%06d", n)
}

// Send OTP for password reset
func (s *Server) sendOTP(w http.ResponseWriter, r *http.Request) {
	var req models.OTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	// Check if user exists
	var userID int
	err := s.db.QueryRow("SELECT id FROM Users WHERE email = ?", req.Email).Scan(&userID)
	if err != nil {
		sendResponse(w, http.StatusNotFound, "User not found", nil)
		return
	}

	// Generate OTP
	otp := generateOTP()

	// Store OTP in database
	_, err = s.db.Exec("INSERT INTO SPN_PasswordResets (user_id, otp_code, is_used) VALUES (?, ?, FALSE)", userID, otp)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Failed to store OTP", nil)
		return
	}

	// TODO: Send OTP via email or SMS
	sendResponse(w, http.StatusOK, "OTP sent successfully", nil)
}

// Verify OTP
func (s *Server) verifyOTP(w http.ResponseWriter, r *http.Request) {
	var req models.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	var userID int
	err := s.db.QueryRow("SELECT user_id FROM SPN_PasswordResets WHERE otp_code = ? AND is_used = FALSE AND created_at >= NOW() - INTERVAL 10 MINUTE", req.OTP).Scan(&userID)
	if err != nil {
		sendResponse(w, http.StatusUnauthorized, "Invalid or expired OTP", nil)
		return
	}

	// Mark OTP as used
	_, err = s.db.Exec("UPDATE SPN_PasswordResets SET is_used = TRUE WHERE otp_code = ?", req.OTP)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Failed to update OTP status", nil)
		return
	}

	sendResponse(w, http.StatusOK, "OTP verified successfully", nil)
}

// Reset password
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	var userID int
	var oldPasswordHash string
	err := s.db.QueryRow("SELECT u.id, u.password_hash FROM Users u JOIN SPN_PasswordResets pr ON u.id = pr.user_id WHERE pr.otp_code = ? AND pr.is_used = TRUE", req.OTP).Scan(&userID, &oldPasswordHash)
	if err != nil {
		sendResponse(w, http.StatusUnauthorized, "Invalid OTP", nil)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Password hashing failed", nil)
		return
	}

	// Ensure new password is different from old password
	if err := bcrypt.CompareHashAndPassword([]byte(oldPasswordHash), []byte(req.NewPassword)); err == nil {
		sendResponse(w, http.StatusBadRequest, "New password must be different from the old password", nil)
		return
	}

	// Update user password
	_, err = s.db.Exec("UPDATE Users SET password_hash = ? WHERE id = ?", hashedPassword, userID)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Failed to reset password", nil)
		return
	}

	// Clean up used OTP records
	_, _ = s.db.Exec("DELETE FROM SPN_PasswordResets WHERE user_id = ?", userID)

	sendResponse(w, http.StatusOK, "Password reset successfully", nil)
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

// Fetch user login details from Users table
func (s *Server) fetchUserLoginDetails(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		sendResponse(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	var user models.User
	err := s.db.QueryRow("SELECT id, email, has_biometrics, COALESCE(device_token, ''), is_blocked, failed_attempts FROM Users WHERE email = ?", email).
		Scan(&user.ID, &user.Email, &user.HasBiometrics, &user.DeviceToken, &user.IsBlocked, &user.FailedAttempts)
	if err != nil {
		if err == sql.ErrNoRows {
			sendResponse(w, http.StatusNotFound, "User not found", nil)
		} else {
			sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		}
		return
	}

	sendResponse(w, http.StatusOK, "User fetched successfully", user)
}

// Fetch user personal details from SPN_UserDetails table
func (s *Server) fetchUserDetails(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" {
		sendResponse(w, http.StatusBadRequest, "Email is required", nil)
		return
	}

	var userID int
	err := s.db.QueryRow("SELECT id FROM Users WHERE email = ?", email).Scan(&userID)
	if err != nil {
		sendResponse(w, http.StatusNotFound, "User not found", nil)
		return
	}

	var userDetails models.UserDetailsRequest
	err = s.db.QueryRow("SELECT user_id, gender, height_cm, weight_kg, age, wakeup_time, bedtime, activity_level FROM UserDetails WHERE user_id = ?", userID).
		Scan(&userDetails.UserID, &userDetails.Gender, &userDetails.HeightCM, &userDetails.WeightKG, &userDetails.Age, &userDetails.WakeupTime, &userDetails.Bedtime, &userDetails.ActivityLevel)
	if err != nil {
		if err == sql.ErrNoRows {
			sendResponse(w, http.StatusNotFound, "User details not found", nil)
		} else {
			sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		}
		return
	}

	sendResponse(w, http.StatusOK, "User details fetched successfully", userDetails)
}
