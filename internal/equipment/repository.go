package equipment

import (
	"context"
	"errors"
	"fmt"

	"github.com/stageops/backend/internal/couch"
)

const (
	docType   = "equipment"
	designDoc = "equipment"
	viewAll   = "all"
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
	var docs []doc
	if err := r.db.ListByView(ctx, designDoc, viewAll, &docs); err != nil {
		return nil, fmt.Errorf("listing equipment: %w", err)
	}
	return docs, nil
}

func (r *CouchDBRepository) FindByID(ctx context.Context, id string) (*doc, error) {
	var equipment doc
	if err := r.db.GetDoc(ctx, id, &equipment); err != nil {
		return nil, mapRepositoryError(err, "fetching equipment")
	}
	if equipment.Type != docType {
		return nil, ErrNotFound
	}
	return &equipment, nil
}

func (r *CouchDBRepository) Create(ctx context.Context, equipment *doc) error {
	if err := r.db.PutDoc(ctx, equipment.ID, equipment); err != nil {
		return mapRepositoryError(err, "creating equipment")
	}
	return nil
}

func (r *CouchDBRepository) Update(ctx context.Context, equipment *doc) error {
	if err := r.db.PutDoc(ctx, equipment.ID, equipment); err != nil {
		return mapRepositoryError(err, "updating equipment")
	}
	return nil
}

func (r *CouchDBRepository) Delete(ctx context.Context, id, rev string) error {
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
