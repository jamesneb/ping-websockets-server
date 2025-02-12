package auth_utilities

import (
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/bcrypt"
	"io"
	"math/big"
	"net/http"
	"os"
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

type LoginPayload struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type User struct {
	FirstName string
	LastName  string
	Email     string
	Username  string
	Password  string
	// Add other fields if needed
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

func GenerateAuthCode(userID string, redirectURI string) (string, error) {
	var clientID = "ping_app"
	if userID == "" || clientID == "" || redirectURI == "" {
		return "", fmt.Errorf("all parameters are required")
	}

	// Generate random authorization code
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}
	authCode := base64.RawURLEncoding.EncodeToString(randomBytes)

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, "postgresql://localhost:5432/ping")
	if err != nil {
		return "", fmt.Errorf("error connecting to db: %v", err)
	}
	defer dbpool.Close()

	// Store the authorization code
	_, err = dbpool.Exec(ctx, `
        INSERT INTO authorization_codes 
        (code, user_id, client_id, redirect_uri, expires_at, is_used)
        VALUES ($1, $2, $3, $4, $5, false)`,
		authCode,
		userID,
		clientID,
		redirectURI,
		time.Now().Add(time.Minute*10), // Auth codes typically expire quickly, e.g., 10 minutes
	)
	if err != nil {
		return "", fmt.Errorf("failed to store authorization code: %v", err)
	}

	return authCode, nil
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

func LoginValid(payload LoginPayload) bool {
	if payload.Password == "" || payload.Username == "" {
		return false
	}

	dbpool, err := pgxpool.New(context.Background(), "postgresql://localhost:5432/ping")
	if err != nil {
		fmt.Println("Database connection error:", err)
		return false
	}
	defer dbpool.Close()

	ctx := context.Background()
	tx, err := dbpool.Begin(ctx)
	if err != nil {
		fmt.Println("Transaction error:", err)
		return false
	}
	defer tx.Rollback(ctx)

	var storedPassword string
	fmt.Println(payload.Username)
	checkSQL := `SELECT password FROM users WHERE username = $1`
	fmt.Println(checkSQL)
	err = tx.QueryRow(ctx, checkSQL, payload.Username).Scan(&storedPassword)

	if err == pgx.ErrNoRows {
		fmt.Println("User not found")
		return false
	}

	if err != nil {
		fmt.Println("Query error:", err)
		return false
	}
	fmt.Println(storedPassword)
	fmt.Println(payload.Password)
	hashed, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		fmt.Println("Hash error:", err)
		return false
	}
	fmt.Println(string(hashed))
	fmt.Println(string(storedPassword))
	if nil != bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(payload.Password)) {
		fmt.Println("Password mismatch")
		return false
	}

	if err := tx.Commit(ctx); err != nil {
		fmt.Println("Commit error:", err)
		return false
	}

	return true
}

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code"`
	RedirectURI  string `json:"redirect_uri"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func HandleTokenExchange(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		sendError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Only POST method is allowed")
		return
	}

	var req TokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendError(w, http.StatusBadRequest, "invalid_request", "Invalid request body")
		return
	}

	// Verify grant type
	if req.GrantType != "authorization_code" {
		sendError(w, http.StatusBadRequest, "unsupported_grant_type", "Only authorization code grant type is supported")
		return
	}

	// Verify client credentials
	if err := verifyClientCredentials(req.ClientID, req.ClientSecret); err != nil {
		sendError(w, http.StatusUnauthorized, "invalid_client", "Invalid client credentials")
		return
	}

	// Validate authorization code
	authCode, err := validateAuthorizationCode(req.Code)
	if err != nil {
		sendError(w, http.StatusBadRequest, "invalid_grant", "Invalid or expired authorization code")
		return
	}

	// Verify redirect URI matches
	if authCode.RedirectURI != req.RedirectURI {
		sendError(w, http.StatusBadRequest, "invalid_grant", "Redirect URI mismatch")
		return
	}

	// Generate tokens
	accessToken, err := generateAccessToken(authCode.UserID, req.ClientID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Error generating access token")
		return
	}

	refreshToken, err := generateRefreshToken(authCode.UserID, req.ClientID)
	if err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Error generating refresh token")
		return
	}

	// Save tokens
	if err := saveTokens(accessToken, refreshToken, authCode.UserID, req.ClientID); err != nil {
		sendError(w, http.StatusInternalServerError, "server_error", "Error saving tokens")
		return
	}

	// Invalidate used authorization code
	if err := invalidateAuthorizationCode(req.Code); err != nil {
		// Log error but don't return it to client
		// Consider implications of code being potentially reusable
		fmt.Errorf("Failed to invalidate authorization code", "error", err)
	}

	// Send successful response
	response := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600, // 1 hour
		RefreshToken: refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func sendError(w http.ResponseWriter, status int, error string, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:            error,
		ErrorDescription: description,
	})
}

// AuthCode represents stored authorization code data
type AuthCode struct {
	Code        string
	UserID      string
	ClientID    string
	RedirectURI string
	ExpiresAt   time.Time
}

func verifyClientCredentials(clientID, clientSecret string) error {
	if clientID == "" || clientSecret == "" {
		return fmt.Errorf("empty credentials")
	}

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, "postgresql://localhost:5432/ping")
	if err != nil {
		return fmt.Errorf("error connecting to db: %v", err)
	}
	defer dbpool.Close()

	var storedSecret string
	err = dbpool.QueryRow(ctx,
		"SELECT secret FROM oauth_clients WHERE client_id = $1",
		clientID).Scan(&storedSecret)

	if err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("invalid client credentials")
		}
		return fmt.Errorf("database error: %v", err)
	}

	// Compare secrets using constant time comparison
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(storedSecret)) != 1 {
		return fmt.Errorf("invalid client credentials")
	}

	return nil
}
func validateAuthorizationCode(code string) (*AuthCode, error) {
	if code == "" {
		return nil, fmt.Errorf("empty authorization code")
	}

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, "postgresql://localhost:5432/ping")
	if err != nil {
		return nil, fmt.Errorf("error connecting to db: %v", err)
	}
	defer dbpool.Close()

	var authCode AuthCode
	err = dbpool.QueryRow(ctx, `
        SELECT code, user_id, client_id, redirect_uri, expires_at
        FROM authorization_codes
        WHERE code = $1 AND expires_at > NOW() AND is_used = false`,
		code).Scan(
		&authCode.Code,
		&authCode.UserID,
		&authCode.ClientID,
		&authCode.RedirectURI,
		&authCode.ExpiresAt,
	)

	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, fmt.Errorf("invalid or expired authorization code")
		}
		return nil, fmt.Errorf("database error: %v", err)
	}

	// Check if code has expired (double check even though we did in SQL)
	if time.Now().After(authCode.ExpiresAt) {
		return nil, fmt.Errorf("authorization code has expired")
	}

	return &authCode, nil
}

func generateAccessToken(userID, clientID string) (string, error) {
	if userID == "" || clientID == "" {
		return "", fmt.Errorf("userID and clientID are required")
	}

	// Create the claims
	claims := jwt.MapClaims{
		"user_id":   userID,
		"client_id": clientID,
		"exp":       time.Now().Add(time.Hour * 1).Unix(), // Token expires in 1 hour
		"iat":       time.Now().Unix(),                    // Issued at time
		"typ":       "access_token",
	}

	// Create the token with the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Get the secret key from environment variable
	secretKey := []byte(os.Getenv("JWT_SECRET_KEY"))
	if len(secretKey) == 0 {
		return "", fmt.Errorf("JWT secret key not configured")
	}

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenString, nil
}

func generateRefreshToken(userID, clientID string) (string, error) {
	if userID == "" || clientID == "" {
		return "", fmt.Errorf("userID and clientID are required")
	}

	// Generate 32 random bytes
	randomBytes := make([]byte, 32)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %v", err)
	}

	// Convert to base64URL string (removes padding and special chars)
	refreshToken := base64.RawURLEncoding.EncodeToString(randomBytes)

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, "postgresql://localhost:5432/ping")
	if err != nil {
		return "", fmt.Errorf("error connecting to db: %v", err)
	}
	defer dbpool.Close()

	// Store refresh token in database
	_, err = dbpool.Exec(ctx, `
        INSERT INTO refresh_tokens 
        (token, user_id, client_id, expires_at, is_revoked)
        VALUES ($1, $2, $3, $4, false)`,
		refreshToken,
		userID,
		clientID,
		time.Now().Add(time.Hour*24*30), // 30 days expiration
	)
	if err != nil {
		return "", fmt.Errorf("failed to store refresh token: %v", err)
	}

	return refreshToken, nil
}

func saveTokens(accessToken, refreshToken, userID, clientID string) error {
	if accessToken == "" || refreshToken == "" || userID == "" || clientID == "" {
		return fmt.Errorf("all parameters are required")
	}

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, "postgresql://localhost:5432/ping")
	if err != nil {
		return fmt.Errorf("error connecting to db: %v", err)
	}
	defer dbpool.Close()

	// Begin transaction
	tx, err := dbpool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("error starting transaction: %v", err)
	}
	// Defer rollback in case anything fails
	defer tx.Rollback(ctx)

	// Save access token
	_, err = tx.Exec(ctx, `
        INSERT INTO access_tokens 
        (token, user_id, client_id, expires_at)
        VALUES ($1, $2, $3, $4)`,
		accessToken,
		userID,
		clientID,
		time.Now().Add(time.Hour), // 1 hour expiration
	)
	if err != nil {
		return fmt.Errorf("failed to save access token: %v", err)
	}

	// Save refresh token
	_, err = tx.Exec(ctx, `
        INSERT INTO refresh_tokens 
        (token, user_id, client_id, expires_at, is_revoked)
        VALUES ($1, $2, $3, $4, false)
        ON CONFLICT (token) DO NOTHING`, // In case it was already saved by generateRefreshToken
		refreshToken,
		userID,
		clientID,
		time.Now().Add(time.Hour*24*30), // 30 days expiration
	)
	if err != nil {
		return fmt.Errorf("failed to save refresh token: %v", err)
	}

	// Commit transaction
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %v", err)
	}

	return nil
}

func invalidateAuthorizationCode(code string) error {
	if code == "" {
		return fmt.Errorf("authorization code is required")
	}

	ctx := context.Background()
	dbpool, err := pgxpool.New(ctx, "postgresql://localhost:5432/ping")
	if err != nil {
		return fmt.Errorf("error connecting to db: %v", err)
	}
	defer dbpool.Close()

	// Update the authorization code to mark it as used
	result, err := dbpool.Exec(ctx, `
        UPDATE authorization_codes 
        SET is_used = true 
        WHERE code = $1 AND is_used = false`,
		code,
	)

	if err != nil {
		return fmt.Errorf("failed to invalidate authorization code: %v", err)
	}

	// Check if any row was actually updated
	rowsAffected := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("authorization code not found or already used")
	}

	return nil
}
