package team

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/couch"
	"github.com/stageops/backend/internal/tenant"
)

const docType = "member"
const designDoc = "team"
const viewByTheatre = "by_theatre"

type Repository struct {
	db *couch.Client
}

func NewRepository(cfg couch.Config) *Repository {
	return &Repository{db: couch.New(cfg)}
}

func (r *Repository) List(ctx context.Context) ([]Member, error) {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	var docs []doc
	if err := r.db.ListByViewKey(ctx, designDoc, viewByTheatre, theatreID, &docs); err != nil {
		return nil, fmt.Errorf("listing team members: %w", err)
	}
	return toPublicSlice(docs), nil
}

func (r *Repository) FindByID(ctx context.Context, id string) (*Member, error) {
	d, err := r.findDocByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return toPublic(d), nil
}

func (r *Repository) Create(ctx context.Context, input *Input) (*Member, error) {
	id := fmt.Sprintf("member::%s", uuid.New().String())
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	d := &doc{
		ID:          id,
		Type:        docType,
		TheatreID:   theatreID,
		Name:        input.Name,
		Role:        input.Role,
		Avatar:      input.Avatar,
		Email:       input.Email,
		Phone:       input.Phone,
		Permissions: nilToEmpty(input.Permissions),
	}

	if err := r.db.PutDoc(ctx, id, d); err != nil {
		return nil, fmt.Errorf("creating member: %w", err)
	}
	return toPublic(d), nil
}

func (r *Repository) Update(ctx context.Context, id string, input *Input) (*Member, error) {
	current, err := r.findDocByID(ctx, id)
	if err != nil {
		return nil, err
	}

	current.Name = input.Name
	current.Role = input.Role
	current.Avatar = input.Avatar
	current.Email = input.Email
	current.Phone = input.Phone
	current.Permissions = nilToEmpty(input.Permissions)

	if err := r.db.PutDoc(ctx, id, current); err != nil {
		return nil, fmt.Errorf("updating member: %w", err)
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
		return fmt.Errorf("deleting member: %w", err)
	}
	return nil
}

func (r *Repository) findDocByID(ctx context.Context, id string) (*doc, error) {
	var current doc
	if err := r.db.GetDoc(ctx, id, &current); err != nil {
		if errors.Is(err, couch.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("fetching member %s: %w", id, err)
	}
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil || current.Type != docType || current.TheatreID != theatreID {
		return nil, ErrNotFound
	}
	return &current, nil
}
