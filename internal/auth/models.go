package auth

import "time"

// User is the CouchDB document stored under id "user::<uuid>".
type User struct {
	ID                        string     `json:"_id"`
	Rev                       string     `json:"_rev,omitempty"`
	Type                      string     `json:"type"`
	Email                     string     `json:"email"`
	TheatreID                 string     `json:"theatre_id"`
	Role                      string     `json:"role"`
	AssignedModules           []string   `json:"assigned_modules"`
	PasswordHash              string     `json:"password_hash"`
	EmailVerificationRequired bool       `json:"email_verification_required"`
	EmailVerifiedAt           *time.Time `json:"email_verified_at,omitempty"`
	VerificationTokenHash     string     `json:"verification_token_hash,omitempty"`
	VerificationExpiresAt     *time.Time `json:"verification_expires_at,omitempty"`
	FailedAttempts            int        `json:"failed_attempts"`
	LockedUntil               *time.Time `json:"locked_until,omitempty"`
	CreatedAt                 time.Time  `json:"created_at"`
	UpdatedAt                 time.Time  `json:"updated_at"`
}

// UserPublic is returned to the client — no sensitive fields.
type UserPublic struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	TheatreID       string    `json:"theatre_id"`
	Role            string    `json:"role"`
	AssignedModules []string  `json:"assigned_modules"`
	CreatedAt       time.Time `json:"created_at"`
}

// Session stores the server-side state of a refresh-token family.
// Only SHA-256 token fingerprints are persisted.
type Session struct {
	ID                  string     `json:"_id"`
	Rev                 string     `json:"_rev,omitempty"`
	Type                string     `json:"type"`
	UserID              string     `json:"user_id"`
	TheatreID           string     `json:"theatre_id"`
	RefreshTokenHash    string     `json:"refresh_token_hash"`
	PreviousRefreshHash string     `json:"previous_refresh_hash,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	LastUsedAt          time.Time  `json:"last_used_at"`
	ExpiresAt           time.Time  `json:"expires_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
}

// TokenPair is returned after a successful authentication or token rotation.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// Device is an authorized installation that may receive offline grants.
type Device struct {
	ID        string     `json:"_id"`
	Rev       string     `json:"_rev,omitempty"`
	Type      string     `json:"type"`
	UserID    string     `json:"user_id"`
	TheatreID string     `json:"theatre_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// DevicePublic is safe to return to authenticated clients.
type DevicePublic struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// OfflineGrant contains a signed authorization snapshot for local use.
type OfflineGrant struct {
	Token     string       `json:"token"`
	Device    DevicePublic `json:"device"`
	ExpiresAt time.Time    `json:"expires_at"`
}
