package main

import (
	"context"
	"fmt"
	"github.com/go-chi/render"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"log"
	"net/http"
	"net/url"
	"websocket-server/auth/auth_utilities"
	"websocket-server/auth/constants"
)

// Upgrader to handle WebSocket connections
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allows connections from any origin
	},
}

// authorize handles the first step in OAuth 2.0: Authorization Request
func authorize(w http.ResponseWriter, r *http.Request) {
	// Decode the incoming OAuth request payload
	var payload auth_utilities.OauthPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Validate the OAuth request
	if !auth_utilities.IsValidOauthPayload(&payload) {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	// Check if the user is logged in
	sessionCookie, err := r.Cookie("session_id")
	var sessionID string
	if err == nil {
		sessionID = sessionCookie.Value
	}
	authResult := auth_utilities.GetSession(sessionID)
	loggedIn, message := authResult.Result()
	if loggedIn {
		// User is logged in → Generate authorization code
		authCode := auth_utilities.GenerateAuthCode()
		err := auth_utilities.SaveAuthCode(authCode, payload.ClientID, message)

		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		// Redirect user to client with auth code
		redirectURL, _ := url.Parse(payload.RedirectURI)
		params := url.Values{}
		params.Add("code", authCode)
		params.Add("state", payload.State)
		redirectURL.RawQuery = params.Encode()

		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	} else {
		// User is not logged in → Redirect to login page
		loginURL, _ := url.Parse(constants.LoginURL)
		params := url.Values{}
		params.Add("redirect_uri", payload.RedirectURI)
		params.Add("state", payload.State)
		loginURL.RawQuery = params.Encode()
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
		return
	}

}

// Handles incoming WebSocket connections
func handleConnection(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Incoming connection from:", r.RemoteAddr)

	// Upgrade HTTP connection to WebSocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}
	defer conn.Close()

	fmt.Println("New WebSocket connection established")

	for {
		// Read message
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			break // Exit loop if client disconnects
		}

		// Log received message
		fmt.Println("Received message:", string(p))
		var passCode = auth_utilities.GeneratePasscode(12)

		var ctx = context.Background()
		rdb := redis.NewClient(&redis.Options{
			Addr:     "redis-14291.c10.us-east-1-4.ec2.redns.redis-cloud.com:14291",
			Password: "rc3GxT3V1kb2QFJnHGpAE1bg3ODJL92l", // no password set
			DB:       0,                                  // use default DB
		})

		err = rdb.Set(ctx, "passcode", passCode, 0).Err()
		if err != nil {
			print(err)
		} else {
			fmt.Println("Passcode generated: ", passCode)
		}

		var participant = "John Doe is in this call..."
		participantbyte := []byte(participant)
		// Echo message back
		err = conn.WriteMessage(messageType, participantbyte)
		if err != nil {
			log.Println("Error sending message:", err)
			break
		}
	}
}

func main() {
	// Set up WebSocket route
	http.HandleFunc("/ws", handleConnection)

	// Start the server and keep it running
	serverAddress := ":8080"
	fmt.Println("WebSocket server listening on ws://localhost" + serverAddress)

	err := http.ListenAndServe(serverAddress, nil)
	if err != nil {
		log.Fatal("ListenAndServe error:", err) // Logs the error and exits
	}
}
