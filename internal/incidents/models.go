package incidents

import (
	"errors"
	"time"
)

var (
	ErrNotFound       = errors.New("incident not found")
	ErrInvalidStatus   = errors.New("invalid incident status")
	ErrInvalidSeverity = errors.New("invalid incident severity")
)

var validStatuses = map[string]bool{
	"open": true, "in-progress": true, "resolved": true, "closed": true,
}
var validSeverities = map[string]bool{
	"low": true, "medium": true, "high": true, "critical": true,
}

type doc struct {
	ID              string     `json:"_id"`
	Rev             string     `json:"_rev,omitempty"`
	Type            string     `json:"type"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	EquipmentID     string     `json:"equipmentId,omitempty"`
	ReportedBy      string     `json:"reportedBy"`
	Timestamp       time.Time  `json:"timestamp"`
	ResolvedAt      *time.Time `json:"resolvedAt,omitempty"`
	ResolutionNotes string     `json:"resolutionNotes,omitempty"`
	Images          []string   `json:"images,omitempty"`
}

type Incident struct {
	ID              string     `json:"id"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	EquipmentID     string     `json:"equipmentId,omitempty"`
	ReportedBy      string     `json:"reportedBy"`
	Timestamp       time.Time  `json:"timestamp"`
	ResolvedAt      *time.Time `json:"resolvedAt,omitempty"`
	ResolutionNotes string     `json:"resolutionNotes,omitempty"`
	Images          []string   `json:"images,omitempty"`
}

type Input struct {
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	EquipmentID     string     `json:"equipmentId"`
	ReportedBy      string     `json:"reportedBy"`
	Timestamp       *time.Time `json:"timestamp"`
	ResolvedAt      *time.Time `json:"resolvedAt"`
	ResolutionNotes string     `json:"resolutionNotes"`
	Images          []string   `json:"images"`
}

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func toPublic(d *doc) *Incident {
	return &Incident{
		ID:              d.ID,
		Title:           d.Title,
		Description:     d.Description,
		Severity:        d.Severity,
		Status:          d.Status,
		EquipmentID:     d.EquipmentID,
		ReportedBy:      d.ReportedBy,
		Timestamp:       d.Timestamp,
		ResolvedAt:      d.ResolvedAt,
		ResolutionNotes: d.ResolutionNotes,
		Images:          d.Images,
	}
}

func toPublicSlice(docs []doc) []Incident {
	out := make([]Incident, len(docs))
	for i := range docs {
		out[i] = *toPublic(&docs[i])
	}
	return out
}
