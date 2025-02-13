// internal/api/handler/auth.go
package handler

import (
	"encoding/json"
	"net/http"
	"ping-websocket-server/internal/domain/auth"
	"ping-websocket-server/pkg/errors"
)

type AuthHandler struct {
	authService *auth.AuthService
}

func NewAuthHandler(as *auth.AuthService) *AuthHandler {
	return &AuthHandler{
		authService: as,
	}
}

func (h *AuthHandler) SignUp(w http.ResponseWriter, r *http.Request) {
	var req auth.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, errors.NewBadRequestError("invalid request payload"), http.StatusBadRequest)
		return
	}

	resp, err := h.authService.SignUp(r.Context(), &req)
	if err != nil {
		switch e := err.(type) {
		case *errors.ValidationError:
			WriteError(w, e, http.StatusBadRequest)
		case *errors.ConflictError:
			WriteError(w, e, http.StatusConflict)
		default:
			WriteError(w, errors.NewInternalError(), http.StatusInternalServerError)
		}
		return
	}

	WriteJSON(w, resp, http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req auth.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, errors.NewBadRequestError("invalid request payload"), http.StatusBadRequest)
		return
	}

	resp, err := h.authService.Login(r.Context(), &req)
	if err != nil {
		switch e := err.(type) {
		case *errors.ValidationError:
			WriteError(w, e, http.StatusBadRequest)
		case *errors.AuthenticationError:
			WriteError(w, e, http.StatusUnauthorized)
		default:
			WriteError(w, errors.NewInternalError(), http.StatusInternalServerError)
		}
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    resp.SessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	WriteJSON(w, resp, http.StatusOK)
}

func (h *AuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	var req auth.OAuthRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, errors.NewBadRequestError("invalid request payload"), http.StatusBadRequest)
		return
	}

	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		WriteError(w, errors.NewAuthenticationError("no session found"), http.StatusUnauthorized)
		return
	}

	resp, err := h.authService.Authorize(r.Context(), sessionCookie.Value, &req)
	if err != nil {
		switch e := err.(type) {
		case *errors.ValidationError:
			WriteError(w, e, http.StatusBadRequest)
		case *errors.AuthenticationError:
			WriteError(w, e, http.StatusUnauthorized)
		default:
			WriteError(w, errors.NewInternalError(), http.StatusInternalServerError)
		}
		return
	}

	// Redirect with auth code
	http.Redirect(w, r, resp.RedirectURI, http.StatusFound)
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	sessionCookie, err := r.Cookie("session_id")
	if err != nil {
		WriteError(w, errors.NewAuthenticationError("no session found"), http.StatusUnauthorized)
		return
	}

	if err := h.authService.Logout(r.Context(), sessionCookie.Value); err != nil {
		WriteError(w, errors.NewInternalError(), http.StatusInternalServerError)
		return
	}

	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	WriteJSON(w, map[string]string{"message": "Successfully logged out"}, http.StatusOK)
}
