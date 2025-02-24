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

	"gopkg.in/gomail.v2"
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

//to send the email to the user

func sendEmailOTP(email, otp string) error {
	//just to check what the issueis here
	smtpEmail := os.Getenv("SMTP_EMAIL")
	smtpPass := os.Getenv("SMTP_PASSWORD")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	// Debug logs
	log.Printf(" Debug: SMTP_EMAIL = %s", smtpEmail)
	log.Printf(" Debug: SMTP_PASSWORD is set: %t", smtpPass != "")
	log.Printf(" Debug: SMTP_HOST = %s", smtpHost)
	log.Printf(" Debug: SMTP_PORT = %s", smtpPort)

	if smtpEmail == "" || smtpPass == "" {
		log.Println(" SMTP credentials are missing! Check your .env file.")
		return fmt.Errorf("SMTP credentials are missing")
	}

	m := gomail.NewMessage()
	m.SetHeader("From", os.Getenv("SMTP_EMAIL"))
	m.SetHeader("To", email)
	m.SetHeader("Subject", "Your OTP Code")
	m.SetBody("text/plain", fmt.Sprintf("Your OTP code is: %s\nIt is valid for 10 minutes.", otp))

	d := gomail.NewDialer("smtp.gmail.com", 587, os.Getenv("SMTP_EMAIL"), os.Getenv("SMTP_PASSWORD"))
	// return d.DialAndSend(m)
	err := d.DialAndSend(m)
	if err != nil {
		log.Printf("Error sending email: %v", err) // Log the actual error
		return err
	}

	log.Println("Email sent successfully!")
	return nil
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
	err = sendEmailOTP(req.Email, otp)
	if err != nil {
		sendResponse(w, http.StatusInternalServerError, "Failed to send OTP email", nil)
		return
	}

	sendResponse(w, http.StatusOK, "OTP sent successfully to email", nil)
}

// Verify OTP*****************************************************************************
func (s *Server) verifyOTP(w http.ResponseWriter, r *http.Request) {
	var req models.VerifyOTPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}

	var userID, failedAttempts int
	var isBlocked bool

	// 🚀 Ensure DB is not nil before transaction
	if s.db == nil {
		log.Fatal(" Database connection is nil.")
		sendResponse(w, http.StatusInternalServerError, "Database connection error", nil)
		return
	}

	// 🟢 Begin transaction
	tx, err := s.db.Begin()
	if err != nil {
		log.Println(" Error starting transaction:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}
	defer tx.Rollback() // Ensure rollback on failure

	// 🔍 Step 1: Fetch user ID from OTP
	err = tx.QueryRow(`
		SELECT user_id FROM PasswordResets 
		WHERE otp_code = ? AND is_used = FALSE 
		AND created_at >= NOW() - INTERVAL 10 MINUTE 
		FOR UPDATE`, req.OTP).Scan(&userID)

	if err == sql.ErrNoRows {
		log.Println(" OTP does not exist or is expired.")
		sendResponse(w, http.StatusUnauthorized, "Invalid or expired OTP", nil)
		return
	} else if err != nil {
		log.Println(" Error fetching OTP:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}

	log.Println(" User found from OTP:", userID)

	// Step 2: Ensure user exists in LoginStatus
	err = tx.QueryRow(`SELECT is_blocked, failed_attempts FROM LoginStatus WHERE user_id = ? FOR UPDATE`, userID).Scan(&isBlocked, &failedAttempts)

	if err == sql.ErrNoRows {
		log.Println(" No entry in LoginStatus for user:", userID, "Creating new record.")
		_, err = tx.Exec("INSERT INTO LoginStatus (user_id, failed_attempts, is_blocked) VALUES (?, 0, FALSE)", userID)
		if err != nil {
			log.Println(" Error creating LoginStatus entry:", err)
			sendResponse(w, http.StatusInternalServerError, "Database error", nil)
			return
		}
		failedAttempts = 0
		isBlocked = false
	} else if err != nil {
		log.Println(" Error fetching LoginStatus:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}
	log.Println("🔍 LoginStatus - User:", userID, "| Blocked:", isBlocked, "| Failed Attempts:", failedAttempts)

	//  Step 3: If user is already blocked, deny access immediately
	if isBlocked {
		log.Println(" User is already blocked:", userID)
		sendResponse(w, http.StatusForbidden, "Your account is blocked due to multiple failed attempts", nil)
		return
	}

	//  Step 4: Handle Incorrect OTP Attempts
	if userID == 0 {
		log.Println(" Invalid OTP, user ID is 0")
		sendResponse(w, http.StatusUnauthorized, "Invalid or expired OTP", nil)
		return
	}

	// Increment failed attempts and check affected rows
	result, err := tx.Exec("UPDATE LoginStatus SET failed_attempts = failed_attempts + 1 WHERE user_id = ?", userID)
	if err != nil {
		log.Println(" Failed to update failed attempts:", err)
		sendResponse(w, http.StatusInternalServerError, "Failed to update failed attempts", nil)
		return
	}
	rowsAffected, _ := result.RowsAffected()
	log.Println(" Rows affected by failed_attempts update:", rowsAffected)
	if rowsAffected == 0 {
		log.Println(" WARNING: No rows updated! Is user_id correct?", userID)
		sendResponse(w, http.StatusInternalServerError, "Failed to update attempts", nil)
		return
	}

	//  Fetch updated failed attempts count
	err = tx.QueryRow("SELECT failed_attempts FROM LoginStatus WHERE user_id = ?", userID).Scan(&failedAttempts)
	if err != nil {
		log.Println(" Failed to fetch failed attempts:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}

	log.Println(" Updated Failed Attempts for user", userID, ":", failedAttempts)

	// Step 5: Block user after 3 failed attempts
	if failedAttempts >= 3 {
		_, err = tx.Exec("UPDATE LoginStatus SET is_blocked = TRUE WHERE user_id = ?", userID)
		if err != nil {
			log.Println(" Failed to block user:", err)
			sendResponse(w, http.StatusInternalServerError, "Failed to block user", nil)
			return
		}
		log.Println(" User blocked due to too many failed attempts:", userID)
		tx.Commit()
		sendResponse(w, http.StatusForbidden, "Too many failed attempts. Your account is blocked.", nil)
		return
	}

	//  Step 6: If OTP is correct, mark it as used and reset failed attempts
	_, err = tx.Exec("UPDATE PasswordResets SET is_used = TRUE WHERE otp_code = ?", req.OTP)
	if err != nil {
		log.Println(" Failed to update OTP status:", err)
		sendResponse(w, http.StatusInternalServerError, "Failed to update OTP status", nil)
		return
	}

	//  Reset failed attempts count to 0
	_, err = tx.Exec("UPDATE LoginStatus SET failed_attempts = 0 WHERE user_id = ?", userID)
	if err != nil {
		log.Println(" Failed to reset failed attempts:", err)
		sendResponse(w, http.StatusInternalServerError, "Failed to reset failed attempts", nil)
		return
	}

	//  Commit transaction
	err = tx.Commit()
	if err != nil {
		log.Println(" Transaction commit failed:", err)
		sendResponse(w, http.StatusInternalServerError, "Transaction error", nil)
		return
	}

	log.Println("OTP verified successfully for user:", userID)
	sendResponse(w, http.StatusOK, "OTP verified successfully", nil)
}

// ********************************************************************************************

// Reset password
func (s *Server) resetPassword(w http.ResponseWriter, r *http.Request) {
	var req models.ResetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendResponse(w, http.StatusBadRequest, "Invalid request format", nil)
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		log.Println(" Error starting transaction:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}
	defer tx.Rollback() // Rollback on failure

	var userID int
	var oldPasswordHash string

	// 🔍 Step 1: Fetch user ID & old password where OTP is **not used**
	err = tx.QueryRow(`
		SELECT u.id, u.password_hash 
		FROM Users u 
		JOIN PasswordResets pr ON u.id = pr.user_id 
		WHERE pr.otp_code = ? AND pr.is_used = FALSE 
		FOR UPDATE`, req.OTP).Scan(&userID, &oldPasswordHash)

	if err == sql.ErrNoRows {
		log.Println(" Invalid OTP or OTP already used:", req.OTP)
		sendResponse(w, http.StatusUnauthorized, "Invalid or expired OTP", nil)
		return
	} else if err != nil {
		log.Println(" Error fetching OTP details:", err)
		sendResponse(w, http.StatusInternalServerError, "Database error", nil)
		return
	}
	log.Println(" User found for OTP:", userID)

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
