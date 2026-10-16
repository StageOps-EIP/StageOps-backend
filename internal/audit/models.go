package audit

import (
	"encoding/json"
	"time"
)

// Action constants for audit log entries.
const (
	ActionRoleChanged        = "ROLE_CHANGED"
	ActionMaterialUpdated    = "MATERIAL_UPDATED"
	ActionIncidentReported   = "INCIDENT_REPORTED"
	ActionUserModulesUpdated = "USER_MODULES_UPDATED"
	ActionUserRegistered     = "USER_REGISTERED"
	ActionLoginSucceeded     = "LOGIN_SUCCEEDED"
	ActionLoginFailed        = "LOGIN_FAILED"
	ActionEmailVerified      = "EMAIL_VERIFIED"
	ActionSessionRefreshed   = "SESSION_REFRESHED"
	ActionSessionRevoked     = "SESSION_REVOKED"
	ActionAllSessionsRevoked = "ALL_SESSIONS_REVOKED"
	ActionOfflineGrantIssued = "OFFLINE_GRANT_ISSUED"
	ActionDeviceRevoked      = "DEVICE_REVOKED"
)

// AuditEntry is a CouchDB document stored under id "audit::<uuid>".
type AuditEntry struct {
	ID         string          `json:"_id"`
	Type       string          `json:"type"`
	TheatreID  string          `json:"theatre_id,omitempty"`
	Action     string          `json:"action"`
	AuthorID   string          `json:"author_id"`
	AuthorRole string          `json:"author_role"`
	TargetID   string          `json:"target_id"`
	Payload    json.RawMessage `json:"payload,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}
