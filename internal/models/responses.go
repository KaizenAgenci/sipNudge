package models

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AuthResponse struct {
	Token string `json:"token"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refreshToken"`
}

type User struct {
	ID             int    `json:"id"`
	Email          string `json:"email"`
	HasBiometrics  bool   `json:"has_biometrics"`
	DeviceToken    string `json:"device_token,omitempty"`
	IsBlocked      bool   `json:"is_blocked"`
	FailedAttempts int    `json:"failed_attempts"`
}
type UserDetailsRequest struct {
	UserID        int     `json:"user_id"`
	Gender        string  `json:"gender"`         // "M", "F", "Other"
	HeightCM      float64 `json:"height_cm"`      // Height in cm
	WeightKG      float64 `json:"weight_kg"`      // Weight in kg
	Age           int     `json:"age"`            // Age in years
	WakeupTime    string  `json:"wakeup_time"`    // Time format: "HH:MM:SS"
	Bedtime       string  `json:"bedtime"`        // Time format: "HH:MM:SS"
	ActivityLevel string  `json:"activity_level"` // "Low", "Moderate", "High"
}

// Request model for sending OTP
type OTPRequest struct {
	Email string `json:"email"`
}

// Request model for verifying OTP
type VerifyOTPRequest struct {
	OTP string `json:"otp"`
}

// Request model for resetting password
type ResetPasswordRequest struct {
	OTP         string `json:"otp"`
	NewPassword string `json:"newPassword"`
}
