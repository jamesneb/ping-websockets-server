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

var rDB *redis.Client

func InitRedis() {
	rDB = redis.NewClient(&redis.Options{Addr: constants.RedisAddr, Password: constants.RedisPasswd, DB: 0})

}

func CheckRedisConnection() error {
	ctx := context.Background()
	_, err := rDB.Ping(ctx).Result()
	return err
}

func SetSession(userID string, sessionID string, expiry time.Duration) {
	ctx := context.Background()
	rDB.Set(ctx, sessionID, userID, expiry)
}

func GetSession(sessionID string) GetSessionResult {
	ctx := context.Background()
	userID, err := rDB.Get(ctx, "session:"+sessionID).Result()
	if errors.Is(err, redis.Nil) {
		return SessionResult{userID, true}
	} else {
		return SessionResult{err.Error(), false}
	}

}

func CreateSession(userID string, expiry time.Duration) string {
	sessionID := GenerateSessionID()
	SetSession(userID, sessionID, expiry)
	return sessionID
}

func GenerateSessionID() string {
	return uuid.New().String()

}

func DeleteSession(sessionID string) error {
	ctx := context.Background()
	return rDB.Del(ctx, "session:"+sessionID).Err()
}

func CheckUserLoginStatus(sessionID string) bool {
	result := GetSession(sessionID)
	loggedIn, _ := result.Result()
	if loggedIn {
		return true
	} else {
		return false
	}

}
func GenerateAuthCode() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Fatal(err)
	}
	return hex.EncodeToString(bytes)
}

func SaveAuthCode(authCode string, clientID string, userID string) error {
	ctx := context.Background()
	err := rDB.Set(ctx, "auth_code:"+authCode, clientID+userID, time.Minute*5).Err()
	if err != nil {
		return err
	}
	return nil
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
