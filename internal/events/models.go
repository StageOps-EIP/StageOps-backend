package events

import (
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("event not found")
	ErrInvalidStatus = errors.New("invalid event status")
)

var validStatuses = map[string]bool{
	"planning": true, "setup": true, "running": true,
	"strike": true, "completed": true,
}

type doc struct {
	ID                string    `json:"_id"`
	Rev               string    `json:"_rev,omitempty"`
	Type              string    `json:"type"`
	Title             string    `json:"title"`
	StartDate         time.Time `json:"startDate"`
	EndDate           time.Time `json:"endDate"`
	Venue             string    `json:"venue"`
	Stage             string    `json:"stage"`
	ChecklistProgress int       `json:"checklistProgress"`
	EquipmentIDs      []string  `json:"equipmentIds"`
	TeamMembers       []string  `json:"teamMembers"`
	Status            string    `json:"status"`
}

type Event struct {
	ID                string    `json:"id"`
	Title             string    `json:"title"`
	StartDate         time.Time `json:"startDate"`
	EndDate           time.Time `json:"endDate"`
	Venue             string    `json:"venue"`
	Stage             string    `json:"stage"`
	ChecklistProgress int       `json:"checklistProgress"`
	EquipmentIDs      []string  `json:"equipmentIds"`
	TeamMembers       []string  `json:"teamMembers"`
	Status            string    `json:"status"`
}

type Input struct {
	Title             string    `json:"title"`
	StartDate         time.Time `json:"startDate"`
	EndDate           time.Time `json:"endDate"`
	Venue             string    `json:"venue"`
	Stage             string    `json:"stage"`
	ChecklistProgress int       `json:"checklistProgress"`
	EquipmentIDs      []string  `json:"equipmentIds"`
	TeamMembers       []string  `json:"teamMembers"`
	Status            string    `json:"status"`
}

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func toPublic(d *doc) *Event {
	return &Event{
		ID:                d.ID,
		Title:             d.Title,
		StartDate:         d.StartDate,
		EndDate:           d.EndDate,
		Venue:             d.Venue,
		Stage:             d.Stage,
		ChecklistProgress: d.ChecklistProgress,
		EquipmentIDs:      nilToEmpty(d.EquipmentIDs),
		TeamMembers:       nilToEmpty(d.TeamMembers),
		Status:            d.Status,
	}
}

func toPublicSlice(docs []doc) []Event {
	out := make([]Event, len(docs))
	for i := range docs {
		out[i] = *toPublic(&docs[i])
	}
	return out
}

func nilToEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
