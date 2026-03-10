package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/couch"
)

const docType = "event"
const designDoc = "events"
const viewAll = "all"

type Repository struct {
	db *couch.Client
}

func NewRepository(cfg couch.Config) *Repository {
	return &Repository{db: couch.New(cfg)}
}

func (r *Repository) List(ctx context.Context) ([]Event, error) {
	var docs []doc
	if err := r.db.ListByView(ctx, designDoc, viewAll, &docs); err != nil {
		return nil, fmt.Errorf("listing events: %w", err)
	}
	return toPublicSlice(docs), nil
}

func (r *Repository) FindByID(ctx context.Context, id string) (*Event, error) {
	var d doc
	if err := r.db.GetDoc(ctx, id, &d); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching event %s: %w", id, err)
	}
	return toPublic(&d), nil
}

func (r *Repository) Create(ctx context.Context, input *Input) (*Event, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}

	id := fmt.Sprintf("event::%s", uuid.New().String())
	d := &doc{
		ID:                id,
		Type:              docType,
		Title:             input.Title,
		StartDate:         input.StartDate,
		EndDate:           input.EndDate,
		Venue:             input.Venue,
		Stage:             input.Stage,
		ChecklistProgress: input.ChecklistProgress,
		EquipmentIDs:      nilToEmpty(input.EquipmentIDs),
		TeamMembers:       nilToEmpty(input.TeamMembers),
		Status:            input.Status,
	}

	if err := r.db.PutDoc(ctx, id, d); err != nil {
		return nil, fmt.Errorf("creating event: %w", err)
	}
	return toPublic(d), nil
}

func (r *Repository) Update(ctx context.Context, id string, input *Input) (*Event, error) {
	if err := validateInput(input); err != nil {
		return nil, err
	}

	var current doc
	if err := r.db.GetDoc(ctx, id, &current); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching event for update: %w", err)
	}

	current.Title = input.Title
	current.StartDate = input.StartDate
	current.EndDate = input.EndDate
	current.Venue = input.Venue
	current.Stage = input.Stage
	current.ChecklistProgress = input.ChecklistProgress
	current.EquipmentIDs = nilToEmpty(input.EquipmentIDs)
	current.TeamMembers = nilToEmpty(input.TeamMembers)
	current.Status = input.Status

	if err := r.db.PutDoc(ctx, id, &current); err != nil {
		return nil, fmt.Errorf("updating event: %w", err)
	}
	return toPublic(&current), nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	var current doc
	if err := r.db.GetDoc(ctx, id, &current); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("fetching event for delete: %w", err)
	}

	if err := r.db.DeleteDoc(ctx, id, current.Rev); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("deleting event: %w", err)
	}
	return nil
}

func validateInput(input *Input) error {
	if input.Title == "" {
		return &ValidationError{Message: "Le champ 'title' est requis."}
	}
	if input.Status != "" && !validStatuses[input.Status] {
		return ErrInvalidStatus
	}
	if input.Status == "" {
		input.Status = "planning"
	}
	return nil
}
