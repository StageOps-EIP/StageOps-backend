package audit

import (
	"encoding/json"
	"time"
)

// Action constants for audit log entries.
const (
	ActionRoleChanged      = "ROLE_CHANGED"
	ActionMaterialUpdated  = "MATERIAL_UPDATED"
	ActionIncidentReported = "INCIDENT_REPORTED"
)

// AuditEntry is a CouchDB document stored under id "audit::<uuid>".
type AuditEntry struct {
	ID         string          `json:"_id"`
	Type       string          `json:"type"`
	Action     string          `json:"action"`
	AuthorID   string          `json:"author_id"`
	AuthorRole string          `json:"author_role"`
	TargetID   string          `json:"target_id"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}
