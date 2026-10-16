package events

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/couch"
	"github.com/stageops/backend/internal/tenant"
)

const docType = "event"
const designDoc = "events"
const viewByTheatre = "by_theatre"

type Repository struct {
	db *couch.Client
}

func NewRepository(cfg couch.Config) *Repository {
	return &Repository{db: couch.New(cfg)}
}

func (r *Repository) List(ctx context.Context) ([]Event, error) {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	var docs []doc
	if err := r.db.ListByViewKey(ctx, designDoc, viewByTheatre, theatreID, &docs); err != nil {
		return nil, fmt.Errorf("listing events: %w", err)
	}
	return toPublicSlice(docs), nil
}

func (r *Repository) FindByID(ctx context.Context, id string) (*Event, error) {
	d, err := r.findDocByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return toPublic(d), nil
}

func (r *Repository) Create(ctx context.Context, input *Input) (*Event, error) {
	id := fmt.Sprintf("event::%s", uuid.New().String())
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	d := &doc{
		ID:                id,
		Type:              docType,
		TheatreID:         theatreID,
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
	current, err := r.findDocByID(ctx, id)
	if err != nil {
		return nil, err
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

	if err := r.db.PutDoc(ctx, id, current); err != nil {
		return nil, fmt.Errorf("updating event: %w", err)
	}
	return toPublic(current), nil
}

func (r *Repository) Delete(ctx context.Context, id string) error {
	current, err := r.findDocByID(ctx, id)
	if err != nil {
		return err
	}

	if err := r.db.DeleteDoc(ctx, id, current.Rev); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return ErrNotFound
		}
		return fmt.Errorf("deleting event: %w", err)
	}
	return nil
}

func (r *Repository) findDocByID(ctx context.Context, id string) (*doc, error) {
	var current doc
	if err := r.db.GetDoc(ctx, id, &current); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching event %s: %w", id, err)
	}
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil || current.Type != docType || current.TheatreID != theatreID {
		return nil, ErrNotFound
	}
	return &current, nil
}
