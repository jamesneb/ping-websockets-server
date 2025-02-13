// internal/config/config.go
package config

type Config struct {
	ServerPort string
	DBUrl      string
	RedisURL   string
	JWTSecret  string
}

func Load() (*Config, error) {
	// Load from env vars or config file
	return &Config{
		ServerPort: ":8080",
		DBUrl:      "your-db-url",
		RedisURL:   "your-redis-url",
		JWTSecret:  "your-jwt-secret",
	}, nil
}
