package incidents

import (
	"errors"
	"time"
)

var (
	ErrNotFound        = errors.New("incident not found")
	ErrConflict        = errors.New("incident conflict")
	ErrInvalidStatus   = errors.New("invalid incident status")
	ErrInvalidSeverity = errors.New("invalid incident severity")
	ErrInvalidModule   = errors.New("invalid incident module")
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
	ProjectID       string     `json:"project_id"`
	Module          string     `json:"module"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	EquipmentID     string     `json:"equipment_id,omitempty"`
	ReportedBy      string     `json:"reported_by"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	ResolutionNotes string     `json:"resolution_notes,omitempty"`
	Images          []string   `json:"images"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Incident struct {
	ID              string     `json:"id"`
	ProjectID       string     `json:"project_id"`
	Module          string     `json:"module"`
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	EquipmentID     string     `json:"equipment_id,omitempty"`
	ReportedBy      string     `json:"reported_by"`
	ResolvedAt      *time.Time `json:"resolved_at,omitempty"`
	ResolutionNotes string     `json:"resolution_notes,omitempty"`
	Images          []string   `json:"images"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

type Input struct {
	Title           string     `json:"title"`
	Description     string     `json:"description"`
	Severity        string     `json:"severity"`
	Status          string     `json:"status"`
	EquipmentID     string     `json:"equipment_id"`
	ResolvedAt      *time.Time `json:"resolved_at"`
	ResolutionNotes string     `json:"resolution_notes"`
	Images          []string   `json:"images"`
}

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func toPublic(d *doc) *Incident {
	return &Incident{
		ID: d.ID, ProjectID: d.ProjectID, Module: d.Module, Title: d.Title,
		Description: d.Description, Severity: d.Severity, Status: d.Status,
		EquipmentID: d.EquipmentID, ReportedBy: d.ReportedBy, ResolvedAt: d.ResolvedAt,
		ResolutionNotes: d.ResolutionNotes, Images: d.Images, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

func toPublicSlice(docs []doc) []Incident {
	result := make([]Incident, 0, len(docs))
	for i := range docs {
		result = append(result, *toPublic(&docs[i]))
	}
	return result
}
