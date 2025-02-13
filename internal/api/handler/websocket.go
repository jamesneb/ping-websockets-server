// internal/api/handler/websocket.go
package handler

import (
	"github.com/gorilla/websocket"
	"net/http"
	"ping-websocket-server/internal/domain/auth"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allow all origins for now
	},
}

type WebSocketHandler struct {
	authService *auth.AuthService
}

func NewWebSocketHandler(as *auth.AuthService) *WebSocketHandler {
	return &WebSocketHandler{
		authService: as,
	}
}

func (h *WebSocketHandler) HandleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		WriteError(w, err, http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	// Handle WebSocket connection
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(messageType, p); err != nil {
			return
		}
	}
}
