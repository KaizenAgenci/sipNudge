package server

import (
	"encoding/json"
	"net/http"
	"os"
	"sipNudge/internal/Constants"
	"sipNudge/internal/models"
	"sipNudge/internal/utils"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
)

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Logger)

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"https://*", "http://*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	r.Get("/health", s.healthHandler)

	r.Get("/api/v1/signIn", s.handleSignIn)
	r.Get("/api/v1/refreshToken", s.handleRefreshToken)
	r.Get("/api/v1/signUp", s.handleSignUp)

	return r
}

func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	jsonResp, _ := json.Marshal(s.db.Health())
	_, _ = w.Write(jsonResp)
}

func (s *Server) handleSignIn(w http.ResponseWriter, r *http.Request) {

	var req models.AuthRequest
	json.NewDecoder(r.Body).Decode(&req)

	//TODO get hashedPassword from the db
	var hashedPassword string
	userExists := true
	if !userExists || bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(req.Password)) != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	}

	//Generate Tokens
	token, err := utils.GenerateTokens(req.Email)
	if err != nil {
		http.Error(w, "error has been logged by us", http.StatusInternalServerError)
	}
	json.NewEncoder(w).Encode(models.AuthResponse{
		Token: token,
	})
}

func (s *Server) handleSignUp(w http.ResponseWriter, r *http.Request) {

	var req models.AuthRequest
	json.NewDecoder(r.Body).Decode(&req)

	// TODO add logic to check if a user exists with same mail id

	_, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "error has been logged we will look into it", http.StatusInternalServerError)
		return
	}

	//TODO add logic to enter email and Password of user with a random uuid into mysqlDB
}

func (s *Server) handleRefreshToken(w http.ResponseWriter, r *http.Request) {

	var req models.RefreshTokenRequest
	json.NewDecoder(r.Body).Decode(&req)

	jwtSecret := os.Getenv(Constants.JwtSecret)
	//parse handleRefresh
	token, err := jwt.Parse(req.RefreshToken, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	//Extract Email from token
	// claims, _ := token.Claims.(jwt.MapClaims)

	//TODO 1. validate token from db
	// 2. Generate new tokens (ROTATE tokens)
	// 3. Remove old Tokens and store new ones in the db
	// 4. return the new token as repsonse

}
