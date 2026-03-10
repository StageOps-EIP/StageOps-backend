package incidents

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/couch"
)

const docType = "incident"
const designDoc = "incidents"
const viewAll = "all"

type Repository struct {
	db *couch.Client
}

func NewRepository(cfg couch.Config) *Repository {
	return &Repository{db: couch.New(cfg)}
}

func (r *Repository) List(ctx context.Context) ([]Incident, error) {
	var docs []doc
	if err := r.db.ListByView(ctx, designDoc, viewAll, &docs); err != nil {
		return nil, fmt.Errorf("listing incidents: %w", err)
	}
	return toPublicSlice(docs), nil
}

func (r *Repository) FindByID(ctx context.Context, id string) (*Incident, error) {
	var d doc
	if err := r.db.GetDoc(ctx, id, &d); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching incident %s: %w", id, err)
	}
	return toPublic(&d), nil
}

func (r *Repository) Create(ctx context.Context, input *Input) (*Incident, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}

	id := fmt.Sprintf("incident::%s", uuid.New().String())
	now := time.Now().UTC()

	ts := now
	if input.Timestamp != nil {
		ts = *input.Timestamp
	}

	d := &doc{
		ID:              id,
		Type:            docType,
		Title:           input.Title,
		Description:     input.Description,
		Severity:        input.Severity,
		Status:          input.Status,
		EquipmentID:     input.EquipmentID,
		ReportedBy:      input.ReportedBy,
		Timestamp:       ts,
		ResolvedAt:      input.ResolvedAt,
		ResolutionNotes: input.ResolutionNotes,
		Images:          input.Images,
	}

	if err := r.db.PutDoc(ctx, id, d); err != nil {
		return nil, fmt.Errorf("creating incident: %w", err)
	}
	return toPublic(d), nil
}

func (r *Repository) Update(ctx context.Context, id string, input *Input) (*Incident, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}

	var current doc
	if err := r.db.GetDoc(ctx, id, &current); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching incident for update: %w", err)
	}

	current.Title = input.Title
	current.Description = input.Description
	current.Severity = input.Severity
	current.Status = input.Status
	current.EquipmentID = input.EquipmentID
	current.ReportedBy = input.ReportedBy
	current.ResolutionNotes = input.ResolutionNotes
	current.Images = input.Images
	if input.ResolvedAt != nil {
		current.ResolvedAt = input.ResolvedAt
	}

	if err := r.db.PutDoc(ctx, id, &current); err != nil {
		return nil, fmt.Errorf("updating incident: %w", err)
	}
	return toPublic(&current), nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	var current doc
	if err := r.db.GetDoc(ctx, id, &current); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("fetching incident for delete: %w", err)
	}

	if err := r.db.DeleteDoc(ctx, id, current.Rev); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("deleting incident: %w", err)
	}
	return nil
}

func validateInput(input *Input) error {
	if input.Title == "" {
		return &ValidationError{Message: "Le champ 'title' est requis."}
	}
	if !validSeverities[input.Severity] {
		return ErrInvalidSeverity
	}
	if input.Status != "" && !validStatuses[input.Status] {
		return ErrInvalidStatus
	}
	if input.Status == "" {
		input.Status = "open"
	}
	return nil
}
