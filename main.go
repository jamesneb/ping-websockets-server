package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"github.com/gorilla/websocket"
	"github.com/redis/go-redis/v9"
	"log"
	"math/big"
	"net/http"
)

func generatePasscode(length int) string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	passcode := make([]byte, length)
	for i := range passcode {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(err)
		}
		passcode[i] = charset[n.Int64()]
	}
	return string(passcode)
}

// Upgrader to handle WebSocket connections
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Allows connections from any origin
	},
}

func authorize(w http.ResponseWriter, r *http.Request) {
	// First, check if the request payload is valid

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
		var passCode = generatePasscode(12)

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
