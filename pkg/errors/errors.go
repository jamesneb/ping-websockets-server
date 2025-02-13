// pkg/errors/errors.go
package errors

type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

func NewValidationError(message string) *ValidationError {
	return &ValidationError{Message: message}
}

type AuthenticationError struct {
	Message string
}

func (e *AuthenticationError) Error() string {
	return e.Message
}

func NewAuthenticationError(message string) *AuthenticationError {
	return &AuthenticationError{Message: message}
}

type ConflictError struct {
	Message string
}

func (e *ConflictError) Error() string {
	return e.Message
}

func NewConflictError(message string) *ConflictError {
	return &ConflictError{Message: message}
}

type InternalError struct {
	Message string
}

func (e *InternalError) Error() string {
	if e.Message == "" {
		return "internal server error"
	}
	return e.Message
}

func NewInternalError() *InternalError {
	return &InternalError{}
}

type BadRequestError struct {
	Message string
}

func (e *BadRequestError) Error() string {
	return e.Message
}

func NewBadRequestError(message string) *BadRequestError {
	return &BadRequestError{Message: message}
}
