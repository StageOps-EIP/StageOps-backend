package equipment

import (
	"errors"
	"time"
)

var (
	ErrNotFound      = errors.New("equipment not found")
	ErrConflict      = errors.New("equipment conflict")
	ErrDMXConflict   = errors.New("DMX address conflict")
	ErrDuplicateName = errors.New("equipment name already exists")
	ErrInvalidStatus = errors.New("invalid equipment status")
	ErrInvalidModule = errors.New("invalid equipment module")
	ErrInvalidKind   = errors.New("invalid equipment kind")
)

var validStatuses = map[string]bool{
	"ok": true, "to-check": true, "hs": true, "repair": true,
}

var validKinds = map[string]map[string]bool{
	"lighting": {"moving-head": true, "fixed": true, "laser": true, "other": true},
	"audio":    {"microphone": true, "wireless": true, "console": true, "speaker": true, "other": true},
	"stage":    {"set": true, "safety": true, "rigging": true, "other": true},
}

type Position struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
	Z float64 `json:"z"`
}

type doc struct {
	ID                string     `json:"_id"`
	Rev               string     `json:"_rev,omitempty"`
	Type              string     `json:"type"`
	ProjectID         string     `json:"project_id"`
	Module            string     `json:"module"`
	Name              string     `json:"name"`
	Kind              string     `json:"kind"`
	QRCode            string     `json:"qr_code,omitempty"`
	Status            string     `json:"status"`
	Location          string     `json:"location,omitempty"`
	Zone              string     `json:"zone,omitempty"`
	ResponsiblePerson string     `json:"responsible_person,omitempty"`
	LastCheck         *time.Time `json:"last_check,omitempty"`
	Position          *Position  `json:"position,omitempty"`
	DMXUniverse       *int       `json:"dmx_universe,omitempty"`
	DMXAddress        *int       `json:"dmx_address,omitempty"`
	DMXChannels       int        `json:"dmx_channels,omitempty"`
	Notes             string     `json:"notes,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Equipment struct {
	ID                string     `json:"id"`
	ProjectID         string     `json:"project_id"`
	Module            string     `json:"module"`
	Name              string     `json:"name"`
	Kind              string     `json:"kind"`
	QRCode            string     `json:"qr_code,omitempty"`
	Status            string     `json:"status"`
	Location          string     `json:"location,omitempty"`
	Zone              string     `json:"zone,omitempty"`
	ResponsiblePerson string     `json:"responsible_person,omitempty"`
	LastCheck         *time.Time `json:"last_check,omitempty"`
	Position          *Position  `json:"position,omitempty"`
	DMXUniverse       *int       `json:"dmx_universe,omitempty"`
	DMXAddress        *int       `json:"dmx_address,omitempty"`
	DMXChannels       int        `json:"dmx_channels,omitempty"`
	Notes             string     `json:"notes,omitempty"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

type Input struct {
	Name              string     `json:"name"`
	Kind              string     `json:"kind"`
	QRCode            string     `json:"qr_code"`
	Status            string     `json:"status"`
	Location          string     `json:"location"`
	Zone              string     `json:"zone"`
	ResponsiblePerson string     `json:"responsible_person"`
	LastCheck         *time.Time `json:"last_check"`
	Position          *Position  `json:"position"`
	DMXUniverse       *int       `json:"dmx_universe"`
	DMXAddress        *int       `json:"dmx_address"`
	DMXChannels       int        `json:"dmx_channels"`
	Notes             string     `json:"notes"`
}

type ValidationError struct{ Message string }

func (e *ValidationError) Error() string { return e.Message }

func toPublic(d *doc) *Equipment {
	return &Equipment{
		ID: d.ID, ProjectID: d.ProjectID, Module: d.Module, Name: d.Name, Kind: d.Kind,
		QRCode: d.QRCode, Status: d.Status, Location: d.Location, Zone: d.Zone,
		ResponsiblePerson: d.ResponsiblePerson, LastCheck: d.LastCheck, Position: d.Position,
		DMXUniverse: d.DMXUniverse, DMXAddress: d.DMXAddress, DMXChannels: d.DMXChannels,
		Notes: d.Notes, CreatedAt: d.CreatedAt, UpdatedAt: d.UpdatedAt,
	}
}

func toPublicSlice(docs []doc) []Equipment {
	result := make([]Equipment, 0, len(docs))
	for i := range docs {
		result = append(result, *toPublic(&docs[i]))
	}
	return result
}
