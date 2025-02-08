package auth_utilities

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"log"
	"math/big"
	"time"
	"websocket-server/auth/constants"
)

type GetSessionResult interface {
	Result() (bool, string)
}

type SessionResult struct {
	message  string
	loggedIn bool
}

func (r SessionResult) Result() (bool, string) {
	return r.loggedIn, r.message
}

type OauthPayload struct {
	CodeChallenge string `json:"code_challenge"`
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	State         string `json:"state"` // Required for CRSF protection
	ResponseType  string `json:"response_type"`
}

type SignupPayload struct {
	Username  string `json:"username"`
	FirstName string `json:"firstName"`
	LastName  string `json:"lastName"`
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type AuthClientStore struct {
	ACS *redis.Client
}

func NewAuthStore(acs *redis.Client) *AuthClientStore {
	if acs == nil {
		acs = redis.NewClient(&redis.Options{
			Addr:     constants.RedisAddr,
			Password: constants.RedisPasswd,
			DB:       0,
		})
	}
	return &AuthClientStore{ACS: acs}
}

func (a *AuthClientStore) CheckRedisConnection() error {
	ctx := context.Background()
	_, err := a.ACS.Ping(ctx).Result()
	return err
}

func (a *AuthClientStore) SetSession(userID string, sessionID string, expiry time.Duration) {
	ctx := context.Background()
	a.ACS.Set(ctx, sessionID, userID, expiry)
}

func (a *AuthClientStore) GetSession(sessionID string) GetSessionResult {
	ctx := context.Background()
	userID, err := a.ACS.Get(ctx, sessionID).Result()

	if err != nil {
		if errors.Is(err, redis.Nil) {
			// Key doesn't exist
			return SessionResult{message: "", loggedIn: false}
		}
		// Other errors
		return SessionResult{message: err.Error(), loggedIn: false}
	}

	// Success case - session exists
	return SessionResult{message: userID, loggedIn: true}
}

func (a *AuthClientStore) CreateSession(userID string, expiry time.Duration) string {
	sessionID := GenerateSessionID()
	a.SetSession(userID, sessionID, expiry)
	return sessionID
}

func GenerateSessionID() string {
	return uuid.New().String()
}

func (a *AuthClientStore) DeleteSession(sessionID string) error {
	ctx := context.Background()
	return a.ACS.Del(ctx, "session:"+sessionID).Err()
}

func (a *AuthClientStore) SaveAuthCode(authCode string, clientID string, userID string) error {
	ctx := context.Background()
	err := a.ACS.Set(ctx, "authcode:"+authCode, clientID+userID, time.Minute*5).Err()
	if err != nil {
		return err
	}
	return nil
}

func CheckUserLoginStatus(sessionID string, store *AuthClientStore) bool {
	result := store.GetSession(sessionID)
	loggedIn, _ := result.Result()
	return loggedIn
}

func GenerateAuthCode() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}

func IsValidOauthPayload(payload *OauthPayload) bool {
	if payload == nil {
		return false
	}
	if payload.CodeChallenge == "" {
		return false
	}
	if payload.ClientID == "" {
		return false
	}
	if payload.RedirectURI == "" {
		return false
	}
	if payload.Scope == "" {
		return false
	}
	if payload.State == "" {
		return false
	}
	if payload.ResponseType == "" {
		return false
	}
	return true
}

func GeneratePasscode(length int) string {
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
