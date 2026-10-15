package tenant

import (
	"context"
	"errors"
)

// ErrMissing is returned when a protected data operation has no tenant scope.
var ErrMissing = errors.New("theatre scope missing")

type contextKey struct{}

// WithTheatreID attaches the authenticated theatre to a request context.
func WithTheatreID(ctx context.Context, theatreID string) context.Context {
	return context.WithValue(ctx, contextKey{}, theatreID)
}

// TheatreID returns the authenticated theatre from a request context.
func TheatreID(ctx context.Context) (string, bool) {
	value, ok := ctx.Value(contextKey{}).(string)
	return value, ok && value != ""
}

// RequireTheatreID returns the authenticated theatre or a typed error.
func RequireTheatreID(ctx context.Context) (string, error) {
	theatreID, ok := TheatreID(ctx)
	if !ok {
		return "", ErrMissing
	}
	return theatreID, nil
}
