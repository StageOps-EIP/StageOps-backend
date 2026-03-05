package auth

import "time"

// User is the CouchDB document stored under id "user::<uuid>".
type User struct {
	ID             string     `json:"_id"`
	Rev            string     `json:"_rev,omitempty"`
	Type           string     `json:"type"`
	Email          string     `json:"email"`
	Role           string     `json:"role"`
	PasswordHash   string     `json:"password_hash"`
	FailedAttempts int        `json:"failed_attempts"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// UserPublic is returned to the client — no sensitive fields.
type UserPublic struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}
