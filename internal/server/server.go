package server

import (
	"fmt"
	"net/http"
	"os"
	"sipNudge/internal/database"
	"strconv"
	"time"

	_ "github.com/joho/godotenv/autoload"

	"github.com/joho/godotenv"
)

type Server struct {
	port int
	db   database.Service
}

func NewServer() *http.Server {
	// Explicitly load the .env file to ensure environment variables are available
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Error loading .env file. Ensure .env is present in the root directory.")
	}

	// TODO: Fix fetching PORT from environment variables
	// PORT should be retrieved correctly from .env and properly validated
	portStr := os.Getenv("PORT")
	fmt.Println("PORT from .env:", portStr) // Debugging: Print PORT value

	port, err := strconv.Atoi(portStr)
	if err != nil {
		fmt.Println("Error converting PORT to integer. Ensure the value exists and is valid in .env.")
		port = 8080 // Default to 8080 if PORT is not set or invalid
	}

	// Initialize server instance
	NewServer := &Server{
		port: port,
		db:   database.New(),
	}

	// Configure and return the HTTP server instance
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", NewServer.port),
		Handler:      NewServer.RegisterRoutes(),
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	return server
}
