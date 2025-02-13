// internal/domain/auth/store.go
package auth

import (
	"context"
	"github.com/redis/go-redis/v9"
	"time"
)

type RedisAuthStore struct {
	redis *redis.Client
}

func NewAuthStore(redis *redis.Client) AuthStore {
	return &RedisAuthStore{
		redis: redis,
	}
}

func (s *RedisAuthStore) CreateSession(username string, duration time.Duration) string {
	sessionID := generateSessionID()
	s.redis.Set(context.Background(), "session:"+sessionID, username, duration)
	return sessionID
}

func (s *RedisAuthStore) GetSession(sessionID string) *AuthResult {
	username, err := s.redis.Get(context.Background(), "session:"+sessionID).Result()
	if err != nil {
		return &AuthResult{Valid: false}
	}
	return &AuthResult{Valid: true, Username: username}
}

func (s *RedisAuthStore) SaveAuthCode(code, clientID, userID string) error {
	// Store auth code with expiration (e.g., 10 minutes)
	err := s.redis.Set(context.Background(), "authcode:"+code,
		map[string]string{"clientID": clientID, "userID": userID},
		10*time.Minute).Err()
	return err
}

// Add the missing DeleteSession method
func (s *RedisAuthStore) DeleteSession(sessionID string) error {
	return s.redis.Del(context.Background(), "session:"+sessionID).Err()
}

func generateSessionID() string {
	// Implement secure session ID generation
	return "session-id" // Placeholder
}
