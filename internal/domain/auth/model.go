// internal/domain/auth/model.go
package auth

type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"`
	Email        string `json:"email"`
	FirstName    string `json:"firstName"`
	LastName     string `json:"lastName"`
}

type SignupRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50"`
	Password  string `json:"password" validate:"required,min=8"`
	Email     string `json:"email" validate:"required,email"`
	FirstName string `json:"firstName" validate:"required"`
	LastName  string `json:"lastName" validate:"required"`
}

type SignupResponse struct {
	Status   int    `json:"status"`
	AuthCode string `json:"authCode"`
	Message  string `json:"message"`
}

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	Status    int    `json:"status"`
	SessionID string `json:"sessionId"`
	Message   string `json:"message"`
}

type OAuthRequest struct {
	ClientID    string `json:"clientId" validate:"required"`
	RedirectURI string `json:"redirectUri" validate:"required,url"`
	State       string `json:"state" validate:"required"`
}

type AuthorizeResponse struct {
	RedirectURI string `json:"redirectUri"`
}

type AuthResult struct {
	Valid    bool
	Username string
}
