

// package main

// import (
// 	"log"
// 	"net/http"
// 	"os"

// 	"sipNudge/internal/database"
// 	"sipNudge/internal/server"

// 	"github.com/joho/godotenv"
// )

// func main() {
// 	// ✅ Load .env file
// 	err := godotenv.Load(".env")
// 	if err != nil {
// 		log.Println("⚠ Warning: Could not load .env file. Ensure it exists.")
// 	}

// 	// ✅ Get PORT from .env or use default
// 	port := os.Getenv("PORT")
// 	if port == "" {
// 		port = "8080" // Default port
// 	}

// 	// ✅ Initialize database connection
// 	db := database.New()

// 	// ✅ Initialize server
// 	srv := server.NewServer(db) // Pass db instance

// 	// ✅ Register routes
// 	router := srv.RegisterRoutes()

// 	// ✅ Start the server
// 	log.Printf("🚀 Server running on http://localhost:%s", port)
// 	err = http.ListenAndServe(":"+port, router) // ✅ Pass the router here

// 	if err != nil && err != http.ErrServerClosed {
// 		log.Fatalf("❌ HTTP server error: %s", err)
// 	}

// 	log.Println("✅ Server has stopped.")
// }

// package main

// import (
//     "log"
//     "net/http"
//     "os"

//     "sipNudge/internal/handlers"
//     "sipNudge/internal/database"

//     "github.com/joho/godotenv"
//     "github.com/gorilla/mux"
// )

// func main() {
//     // Load .env file
//     err := godotenv.Load(".env")
//     if err != nil {
//         log.Println("⚠ Warning: Could not load .env file. Ensure it exists.")
//     }

//     // Get server port from .env or use default
//     port := os.Getenv("PORT")
//     if port == "" {
//         port = "8080" // Default port if not found
//     }

//     // Initialize the database
//     db := database.New()

//     // Create a new router
//     r := mux.NewRouter()

//     // Authentication routes
//     r.HandleFunc("/register", handlers.RegisterHandler(db)).Methods("POST")
//     r.HandleFunc("/login", handlers.LoginHandler(db)).Methods("POST")

//     // OTP routes
//     r.HandleFunc("/send-otp", handlers.SendOTPHandler(db)).Methods("POST")

//     // Start server with the router
//     log.Printf("🚀 Starting server on http://localhost:%s", port)
//     err = http.ListenAndServe(":"+port, r) // ✅ Corrected line to use mux router

//     if err != nil && err != http.ErrServerClosed {
//         log.Fatalf("❌ HTTP server error: %s", err)
//     }

//     log.Println("✅ Server has stopped.")
// }















package main

import (
	"log"
	"net/http"

	"sipNudge/internal/server"
)

func main() {
	
	server := server.NewServer()

	err := server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %s", err)
	}

	log.Println("Server has stopped.")
}
