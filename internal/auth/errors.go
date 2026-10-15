package auth

import "errors"

var (
	ErrUserNotFound        = errors.New("user not found")
	ErrEmailAlreadyExists  = errors.New("email already exists")
	ErrInvalidCredentials  = errors.New("invalid credentials")
	ErrAccountLocked       = errors.New("account locked")
	ErrForbidden           = errors.New("forbidden")
	ErrSessionNotFound     = errors.New("session not found")
	ErrInvalidRefresh      = errors.New("invalid refresh token")
	ErrEmailNotVerified    = errors.New("email not verified")
	ErrInvalidVerification = errors.New("invalid email verification token")
)

// ValidationError carries a user-facing message for input validation failures.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}
