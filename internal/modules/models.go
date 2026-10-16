package modules

import "time"

// Module is a theatre-scoped CouchDB document.
type Module struct {
	ID        string    `json:"_id"`
	Rev       string    `json:"_rev,omitempty"`
	Type      string    `json:"type"`
	TheatreID string    `json:"theatre_id"`
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ModulePublic is the JSON representation returned to API consumers.
type ModulePublic struct {
	Name      string    `json:"name"`
	Active    bool      `json:"active"`
	UpdatedAt time.Time `json:"updated_at"`
}
