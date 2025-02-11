package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"websocket-server/auth/auth_utilities"
	"websocket-server/auth/constants"
        "time"
	"github.com/go-chi/render"
	"github.com/gorilla/websocket"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allows connections from any origin
		},
	}
	authStore *auth_utilities.AuthClientStore
)

func login(w http.ResponseWriter, r *http.Request, store *auth_utilities.AuthClientStore) string {
	var payload auth_utilities.LoginPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)

		return ""
	}

	if !auth_utilities.LoginValid(payload) {
		http.Error(w, "Invalid login", http.StatusBadRequest)
	}
	
	sessionID := store.CreateSession(payload.Username, time.Duration(24))
	w.WriteHeader(http.StatusCreated)
	render.JSON(w, r, map[string]string{"sessionID": sessionID})
	return ""

}

func signUp(w http.ResponseWriter, r *http.Request) {
	var payload auth_utilities.SignupPayload
	if err := render.DecodeJSON(r.Body, &payload); err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)

		return
	}

	if !auth_utilities.IsValidSignupPayload(&payload) {
		http.Error(w, "Invalid request parameters", http.StatusBadRequest)
		return
	}

	dbpool, err := pgxpool.New(context.Background(), "postgresql://localhost:5432/ping")
	if err != nil {
		log.Printf("Unable to connect to database: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer dbpool.Close()

	// Check if user already exists
	checkSQL := "SELECT * from USER where USERNAME = $1"
	tx, err := dbpool.Begin(context.Background())
	if err != nil {
		log.Printf("Unable to start transaction: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer tx.Rollback(context.Background())

	row := tx.QueryRow(context.Background(), checkSQL, payload.Username)
	var exists bool
	if err := row.Scan(&exists); err == nil {
		log.Printf("Tried to sign up for existing user.")
		http.Error(w, "User already exists", http.StatusBadRequest)
		return
	}

	password, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)

	if err == nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		log.Printf("Failed to generate password hash: %v\n", err)
	}

	// Insert new user
	insertSQL := `
        INSERT INTO user (username, password, email, firstname, lastname) 
        VALUES ($1, $2, $3, $4, $5)
    `

	_, err = tx.Exec(context.Background(), insertSQL,
		payload.Username,
		password,
		payload.Email,
		payload.FirstName,
		payload.LastName,
	)

	if err != nil {
		log.Printf("Failed to insert user: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Commit the transaction
	err = tx.Commit(context.Background())
	if err != nil {
		log.Printf("Failed to commit transaction: %v\n", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Return success response
	w.WriteHeader(http.StatusCreated)
	render.JSON(w, r, map[string]string{"message": "User created successfully"})
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
		authCode,_ := auth_utilities.GenerateAuthCode("ping_app", userID)
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

	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r, authStore)

	})

	http.HandleFunc("/signup", func(w http.ResponseWriter, r *http.Request) { signUp(w, r) })
	serverAddress := ":8080"
	fmt.Println("WebSocket server listening on ws://localhost" + serverAddress)

	err := http.ListenAndServe(serverAddress, nil)
	if err != nil {
		log.Fatal("ListenAndServe error:", err)
	}
}
