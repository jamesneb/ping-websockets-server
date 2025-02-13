// internal/api/handler/response.go
package handler

import (
	"encoding/json"
	"log"
	"net/http"
)

// Response wraps data for consistent JSON responses
type Response struct {
	Status  int         `json:"status"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Error wraps error messages for consistent JSON responses
type Error struct {
	Status  int    `json:"status"`
	Message string `json:"message"`
}

// WriteJSON sends a JSON response with the given status code
func WriteJSON(w http.ResponseWriter, data interface{}, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// WriteError sends a JSON error response with the given status code
func WriteError(w http.ResponseWriter, err error, status int) {
	log.Printf("Error: %v", err)
	WriteJSON(w, Error{
		Status:  status,
		Message: err.Error(),
	}, status)
}
