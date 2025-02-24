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
