package auth_utilities

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"io"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
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

type PasswordValidationResult struct {
	IsValid     bool     `json:"is_valid"`
	Strength    float64  `json:"strength"`
	BreachCount int      `json:"breach_count"`
	Suggestions []string `json:"suggestions"`
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

func IsValidSignupPayload(payload *SignupPayload) bool {
	if payload == nil {
		return false
	}
	if payload.Username == "" {
		return false
	}
	if payload.FirstName == "" {
		return false
	}
	if payload.LastName == "" {
		return false
	}
	if payload.Email == "" {
		return false
	}
	if payload.Password == "" {
		return false
	}

	// Validate password strength
	result := ValidatePassword(payload.Password)
	emailRegex := `^[a-zA-Z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$`
	re, err := regexp.Compile(emailRegex)
	if err != nil {
		result.IsValid = false
	}

	// Check if the email matches the pattern
	if !re.MatchString(payload.Email) {
		result.IsValid = false
	}

	// Additional validation for email length
	if len(payload.Email) > 254 {
		result.IsValid = false
	}

	// Additional validation for local part length
	parts := strings.Split(payload.Email, "@")
	if len(parts[0]) > 64 {
		result.IsValid = false
	}
	return result.IsValid
}

func ValidatePassword(password string) PasswordValidationResult {
	result := PasswordValidationResult{
		IsValid:     true,
		Strength:    0.0,
		Suggestions: []string{},
	}

	// Check minimum length
	if len(password) < 12 {
		result.IsValid = false
		result.Suggestions = append(result.Suggestions, "Password must be at least 12 characters long")
	}

	var (
		hasUpper   bool
		hasLower   bool
		hasNumber  bool
		hasSpecial bool
	)

	for _, char := range password {
		switch {
		case unicode.IsUpper(char):
			hasUpper = true
		case unicode.IsLower(char):
			hasLower = true
		case unicode.IsNumber(char):
			hasNumber = true
		case unicode.IsPunct(char) || unicode.IsSymbol(char):
			hasSpecial = true
		}
	}

	// Build suggestions based on missing criteria
	if !hasUpper {
		result.IsValid = false
		result.Suggestions = append(result.Suggestions, "Add uppercase letters")
	}
	if !hasLower {
		result.IsValid = false
		result.Suggestions = append(result.Suggestions, "Add lowercase letters")
	}
	if !hasNumber {
		result.IsValid = false
		result.Suggestions = append(result.Suggestions, "Add numbers")
	}
	if !hasSpecial {
		result.IsValid = false
		result.Suggestions = append(result.Suggestions, "Add special characters")
	}

	// Calculate strength score (0.0 to 1.0)
	strengthFactors := 0
	if hasUpper {
		strengthFactors++
	}
	if hasLower {
		strengthFactors++
	}
	if hasNumber {
		strengthFactors++
	}
	if hasSpecial {
		strengthFactors++
	}
	if len(password) >= 16 {
		strengthFactors++
	}
	result.Strength = float64(strengthFactors) / 5.0

	// Check if password has been compromised
	breachCount, err := checkHaveIBeenPwned(password)
	if err == nil && breachCount > 0 {
		result.IsValid = false
		result.BreachCount = breachCount
		result.Suggestions = append(result.Suggestions,
			fmt.Sprintf("This password appears in %d known data breaches. Please choose a different password", breachCount))
	}

	// Check if email is a valid regex

	return result
}

func checkHaveIBeenPwned(password string) (int, error) {
	// Generate SHA-1 hash of password
	h := sha1.New()
	h.Write([]byte(password))
	hash := strings.ToUpper(hex.EncodeToString(h.Sum(nil)))

	// Get the first 5 characters of the hash
	prefix := hash[:5]
	suffix := hash[5:]

	// Query the API
	resp, err := http.Get("https://api.pwnedpasswords.com/range/" + prefix)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	// Check if our hash suffix exists in the response
	lines := strings.Split(string(body), "\r\n")
	for _, line := range lines {
		parts := strings.Split(line, ":")
		if len(parts) != 2 {
			continue
		}
		if strings.EqualFold(parts[0], suffix) {
			count := 0
			fmt.Sscanf(parts[1], "%d", &count)
			return count, nil
		}
	}

	return 0, nil
}
