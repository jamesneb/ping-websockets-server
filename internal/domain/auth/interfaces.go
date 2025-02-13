// internal/domain/auth/interfaces.go
package auth

import "time"

type Validator interface {
	Validate(interface{}) error
}

type AuthStore interface {
	CreateSession(username string, duration time.Duration) string
	GetSession(sessionID string) *AuthResult
	SaveAuthCode(code, clientID, userID string) error
	DeleteSession(sessionID string) error
}
