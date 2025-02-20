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
