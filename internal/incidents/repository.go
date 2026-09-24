package incidents

import (
	"context"
	"errors"
	"fmt"

	"github.com/stageops/backend/internal/couch"
)

const (
	docType   = "incident"
	designDoc = "incidents"
	viewAll   = "all"
)

type Repository interface {
	List(ctx context.Context) ([]doc, error)
	FindByID(ctx context.Context, id string) (*doc, error)
	Create(ctx context.Context, incident *doc) error
	Update(ctx context.Context, incident *doc) error
	Delete(ctx context.Context, id, rev string) error
}

type CouchDBRepository struct{ db *couch.Client }

func NewRepository(cfg couch.Config) *CouchDBRepository {
	return &CouchDBRepository{db: couch.New(cfg)}
}

func (r *CouchDBRepository) List(ctx context.Context) ([]doc, error) {
	var docs []doc
	if err := r.db.ListByView(ctx, designDoc, viewAll, &docs); err != nil {
		return nil, fmt.Errorf("listing incidents: %w", err)
	}
	return docs, nil
}

func (r *CouchDBRepository) FindByID(ctx context.Context, id string) (*doc, error) {
	var incident doc
	if err := r.db.GetDoc(ctx, id, &incident); err != nil {
		return nil, mapRepositoryError(err, "fetching incident")
	}
	if incident.Type != docType {
		return nil, ErrNotFound
	}
	return &incident, nil
}

func (r *CouchDBRepository) Create(ctx context.Context, incident *doc) error {
	if err := r.db.PutDoc(ctx, incident.ID, incident); err != nil {
		return mapRepositoryError(err, "creating incident")
	}
	return nil
}

func (r *CouchDBRepository) Update(ctx context.Context, incident *doc) error {
	if err := r.db.PutDoc(ctx, incident.ID, incident); err != nil {
		return mapRepositoryError(err, "updating incident")
	}
	return nil
}

func (r *CouchDBRepository) Delete(ctx context.Context, id, rev string) error {
	if err := r.db.DeleteDoc(ctx, id, rev); err != nil {
		return mapRepositoryError(err, "deleting incident")
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
