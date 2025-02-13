// internal/server/server.go
package server

import (
	"context"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-playground/validator/v10"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"net/http"
	"ping-websocket-server/internal/api/handler"
	"ping-websocket-server/internal/config"
	"ping-websocket-server/internal/domain/auth"
	"ping-websocket-server/internal/repository"
)

type Server struct {
	cfg    *config.Config
	router *chi.Mux
	auth   *handler.AuthHandler
	ws     *handler.WebSocketHandler
}

func initDB(cfg *config.Config) *pgxpool.Pool {
	dbpool, err := pgxpool.New(context.Background(), cfg.DBUrl)
	if err != nil {
		panic(err)
	}
	return dbpool
}

func initRedis(cfg *config.Config) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr: cfg.RedisURL,
	})
}

// internal/server/server.go
func New(cfg *config.Config) *Server {
	r := chi.NewRouter()

	// Middleware
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Initialize dependencies
	db := initDB(cfg)
	redisClient := initRedis(cfg)
	validate := validator.New()

	userRepo := repository.NewUserRepository(db)
	authStore := auth.NewAuthStore(redisClient)
	validator := auth.NewValidator(validate) // Use our wrapper
	authService := auth.NewAuthService(userRepo, authStore, validator)

	authHandler := handler.NewAuthHandler(authService)
	wsHandler := handler.NewWebSocketHandler(authService)

	return &Server{
		cfg:    cfg,
		router: r,
		auth:   authHandler,
		ws:     wsHandler,
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.setupRoutes()
	return http.ListenAndServe(s.cfg.ServerPort, s.router)
}

func (s *Server) setupRoutes() {
	s.router.Post("/signup", s.auth.SignUp)
	s.router.Post("/login", s.auth.Login)
	s.router.Post("/authorize", s.auth.Authorize)
	s.router.Get("/ws", s.ws.HandleConnection)
}
