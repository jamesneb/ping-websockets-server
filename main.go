package main

import (
	"context"
	"fmt"
	"github.com/go-chi/render"
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"net/url"
	"websocket-server/auth/auth_utilities"
	"websocket-server/auth/constants"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allows connections from any origin
		},
	}
	authStore *auth_utilities.AuthClientStore
)

func signUp(w http.ResponseWriter, r *http.Request) {
	var payload auth_utilities.SignupPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if !auth_utilities.IsValidSignupPayload(&payload) {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)

	}
	dbpool, err := pgxpool.New(context.Background(), "postgresql://localhost:5432/ping")
	defer dbpool.Close()

  dbpool.AfterConnect = func(ctx context.Context, conn *pgx.Conn)	error {
  	tx, err := conn.Begin(context.Background())
  	if err != nil {
  		return err
  	}
  	defer tx.Rollback(context.Background())
    statement := fmt.Sprintf("INSERT INTO users(username, password, email, firstname, lastname) VALUES (%s, %s, %s, %s, %s) ", *payload.username, *payload.password, *payload.email, *payload.firstName, *payload.lastName  )
  	_, err = tx.Exec(context.Background(), "INSERT INTO users(username, password, email, firstname, lastname) VALUES ()")
  	

}

// authorize handles the first step in OAuth 2.0: Authorization Request
func authorize(w http.ResponseWriter, r *http.Request, store *auth_utilities.AuthClientStore) {
	var payload auth_utilities.OauthPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	if !auth_utilities.IsValidOauthPayload(&payload) {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_id")
	var sessionID string
	if err == nil {
		sessionID = sessionCookie.Value
	}

	// Use provided store instance
	authResult := store.GetSession(sessionID)
	loggedIn, userID := authResult.Result()

	if loggedIn {
		authCode := auth_utilities.GenerateAuthCode()
		err := store.SaveAuthCode(authCode, payload.ClientID, userID)

		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		redirectURL, err := url.Parse(payload.RedirectURI)
		if err != nil {
			http.Error(w, "Invalid redirect URI", http.StatusBadRequest)
			return
		}

		params := url.Values{}
		params.Add("code", authCode)
		params.Add("state", payload.State)
		redirectURL.RawQuery = params.Encode()

		http.Redirect(w, r, redirectURL.String(), http.StatusFound)
	} else {
		loginURL, err := url.Parse(constants.LoginURL)
		if err != nil {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		params := url.Values{}
		params.Add("redirect_uri", payload.RedirectURI)
		params.Add("state", payload.State)
		loginURL.RawQuery = params.Encode()
		http.Redirect(w, r, loginURL.String(), http.StatusFound)
	}
}

func handleConnection(w http.ResponseWriter, r *http.Request, store *auth_utilities.AuthClientStore) {
	fmt.Println("Incoming connection from:", r.RemoteAddr)

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}
	defer conn.Close()

	fmt.Println("New WebSocket connection established")

	// Check session/authentication
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		log.Println("No session cookie found")
		return
	}

	if !auth_utilities.CheckUserLoginStatus(sessionCookie.Value, store) {
		log.Println("User not authenticated")
		return
	}

	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading message:", err)
			break
		}

		fmt.Println("Received message:", string(p))
		passCode := auth_utilities.GeneratePasscode(12)

		// Store passcode in Redis using authStore
		ctx := context.Background()
		err = store.ACS.Set(ctx, "passcode", passCode, 0).Err()
		if err != nil {
			log.Println("Error storing passcode:", err)
		} else {
			fmt.Println("Passcode generated:", passCode)
		}

		participant := "John Doe is in this call..."
		participantByte := []byte(participant)

		err = conn.WriteMessage(messageType, participantByte)
		if err != nil {
			log.Println("Error sending message:", err)
			break
		}
	}
}

func main() {
	// Initialize auth store
	authStore = auth_utilities.NewAuthStore(nil)

	// Check Redis connection
	if err := authStore.CheckRedisConnection(); err != nil {
		log.Fatal("Failed to connect to Redis:", err)
	}

	// Set up routes
	http.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		handleConnection(w, r, authStore)
	})

	http.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		authorize(w, r, authStore)
	})

	serverAddress := ":8080"
	fmt.Println("WebSocket server listening on ws://localhost" + serverAddress)

	err := http.ListenAndServe(serverAddress, nil)
	if err != nil {
		log.Fatal("ListenAndServe error:", err)
	}
}
