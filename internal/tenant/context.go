package tenant

import "context"

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
