package equipment

import (
	"context"
	"errors"
	"fmt"

	"github.com/stageops/backend/internal/couch"
	"github.com/stageops/backend/internal/tenant"
)

const (
	docType       = "equipment"
	designDoc     = "equipment"
	viewByTheatre = "by_theatre"
)

type Repository interface {
	List(ctx context.Context) ([]doc, error)
	FindByID(ctx context.Context, id string) (*doc, error)
	Create(ctx context.Context, equipment *doc) error
	Update(ctx context.Context, equipment *doc) error
	Delete(ctx context.Context, id, rev string) error
}

type CouchDBRepository struct{ db *couch.Client }

func NewRepository(cfg couch.Config) *CouchDBRepository {
	return &CouchDBRepository{db: couch.New(cfg)}
}

func (r *CouchDBRepository) List(ctx context.Context) ([]doc, error) {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	var docs []doc
	if err := r.db.ListByViewKey(ctx, designDoc, viewByTheatre, theatreID, &docs); err != nil {
		return nil, fmt.Errorf("listing equipment: %w", err)
	}
	return docs, nil
}

func (r *CouchDBRepository) FindByID(ctx context.Context, id string) (*doc, error) {
	var equipment doc
	if err := r.db.GetDoc(ctx, id, &equipment); err != nil {
		return nil, mapRepositoryError(err, "fetching equipment")
	}
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil || equipment.Type != docType || equipment.TheatreID != theatreID {
		return nil, ErrNotFound
	}
	return &equipment, nil
}

func (r *CouchDBRepository) Create(ctx context.Context, equipment *doc) error {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return err
	}
	equipment.TheatreID = theatreID
	if err := r.db.PutDoc(ctx, equipment.ID, equipment); err != nil {
		return mapRepositoryError(err, "creating equipment")
	}
	return nil
}

func (r *CouchDBRepository) Update(ctx context.Context, equipment *doc) error {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return err
	}
	if equipment.TheatreID != theatreID {
		return ErrNotFound
	}
	if err := r.db.PutDoc(ctx, equipment.ID, equipment); err != nil {
		return mapRepositoryError(err, "updating equipment")
	}
	return nil
}

func (r *CouchDBRepository) Delete(ctx context.Context, id, rev string) error {
	equipment, err := r.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if equipment.Rev != rev {
		return ErrConflict
	}
	if err := r.db.DeleteDoc(ctx, id, rev); err != nil {
		return mapRepositoryError(err, "deleting equipment")
	}
	return nil
}

func mapRepositoryError(err error, operation string) error {
	switch {
	case errors.Is(err, couch.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, couch.ErrConflict):
		return ErrConflict
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}
