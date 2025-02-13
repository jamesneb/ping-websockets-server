// cmd/server/main.go
package main

import (
	"context"
	"log"
	"ping-websocket-server/internal/config"
	"ping-websocket-server/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	srv := server.New(cfg)
	if err := srv.Start(context.Background()); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
