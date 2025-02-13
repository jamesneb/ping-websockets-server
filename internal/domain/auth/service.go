// internal/domain/auth/service.go
package auth

import (
	"context"
	"golang.org/x/crypto/bcrypt"
	"net/url"
	"ping-websocket-server/pkg/errors"
	"time"
)

type UserRepository interface {
	CreateUser(ctx context.Context, user *SignupRequest) error
	GetUserByUsername(ctx context.Context, username string) (*User, error)
}

type AuthService struct {
	userRepo  UserRepository
	authStore AuthStore
	validator Validator
}

func NewAuthService(ur UserRepository, as AuthStore, v Validator) *AuthService {
	return &AuthService{
		userRepo:  ur,
		authStore: as,
		validator: v,
	}
}

func (s *AuthService) SignUp(ctx context.Context, req *SignupRequest) (*SignupResponse, error) {
	if err := s.validator.Validate(req); err != nil {
		return nil, errors.NewValidationError(err.Error())
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.NewInternalError()
	}

	req.Password = string(hashedPassword)
	if err := s.userRepo.CreateUser(ctx, req); err != nil {
		return nil, err
	}

	authCode, err := GenerateAuthCode(req.Username)
	if err != nil {
		return nil, err
	}

	return &SignupResponse{
		Status:   201,
		AuthCode: authCode,
		Message:  "User created successfully",
	}, nil
}

func (s *AuthService) Login(ctx context.Context, req *LoginRequest) (*LoginResponse, error) {
	if err := s.validator.Validate(req); err != nil {
		return nil, errors.NewValidationError(err.Error())
	}

	user, err := s.userRepo.GetUserByUsername(ctx, req.Username)
	if err != nil {
		return nil, errors.NewAuthenticationError("invalid credentials")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return nil, errors.NewAuthenticationError("invalid credentials")
	}

	// Create session (24 hour duration)
	sessionID := s.authStore.CreateSession(user.Username, 24*time.Hour)

	return &LoginResponse{
		Status:    200,
		SessionID: sessionID,
		Message:   "Login successful",
	}, nil
}

func (s *AuthService) Authorize(ctx context.Context, sessionID string, req *OAuthRequest) (*AuthorizeResponse, error) {
	if err := s.validator.Validate(req); err != nil {
		return nil, errors.NewValidationError(err.Error())
	}

	authResult := s.authStore.GetSession(sessionID)
	if !authResult.Valid {
		return nil, errors.NewAuthenticationError("invalid session")
	}

	authCode, err := GenerateAuthCode(authResult.Username)
	if err != nil {
		return nil, errors.NewInternalError()
	}

	if err := s.authStore.SaveAuthCode(authCode, req.ClientID, authResult.Username); err != nil {
		return nil, errors.NewInternalError()
	}

	redirectURI := BuildRedirectURI(req.RedirectURI, authCode, req.State)

	return &AuthorizeResponse{
		RedirectURI: redirectURI,
	}, nil
}

func (s *AuthService) Logout(ctx context.Context, sessionID string) error {
	if err := s.authStore.DeleteSession(sessionID); err != nil {
		return errors.NewInternalError()
	}
	return nil
}

// Helper function for auth code generation
func GenerateAuthCode(username string) (string, error) {
	// Implementation of auth code generation
	// This could use crypto/rand to generate a secure random string
	return "auth-code-" + username, nil
}

// Helper function to build OAuth redirect URI
func BuildRedirectURI(baseURI, authCode, state string) string {
	u, err := url.Parse(baseURI)
	if err != nil {
		return ""
	}
	q := u.Query()
	q.Set("code", authCode)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
