package projects

import "errors"

var (
	ErrNotFound = errors.New("project not found")
	ErrConflict = errors.New("project revision conflict")
)

// ValidationError describes a client-provided field that is invalid.
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}
