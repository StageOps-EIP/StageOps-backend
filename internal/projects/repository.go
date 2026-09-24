package projects

import (
	"context"
	"errors"
	"fmt"

	"github.com/stageops/backend/internal/couch"
)

const (
	docType   = "project"
	designDoc = "projects"
	viewAll   = "all"
)

// Repository is the persistence contract for projects.
type Repository interface {
	List(ctx context.Context) ([]Project, error)
	FindByID(ctx context.Context, id string) (*Project, error)
	Create(ctx context.Context, project *Project) error
	Update(ctx context.Context, project *Project) error
	Delete(ctx context.Context, id, rev string) error
}

// CouchDBRepository persists projects through the shared CouchDB client.
type CouchDBRepository struct {
	db *couch.Client
}

// NewCouchDBRepository creates a CouchDB-backed project repository.
func NewCouchDBRepository(cfg couch.Config) *CouchDBRepository {
	return &CouchDBRepository{db: couch.New(cfg)}
}

func (r *CouchDBRepository) List(ctx context.Context) ([]Project, error) {
	var projects []Project
	if err := r.db.ListByView(ctx, designDoc, viewAll, &projects); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

func (r *CouchDBRepository) FindByID(ctx context.Context, id string) (*Project, error) {
	var project Project
	if err := r.db.GetDoc(ctx, id, &project); err != nil {
		return nil, mapCouchError(err, "fetching project")
	}
	if project.Type != docType {
		return nil, ErrNotFound
	}
	return &project, nil
}

func (r *CouchDBRepository) Create(ctx context.Context, project *Project) error {
	if err := r.db.PutDoc(ctx, project.ID, project); err != nil {
		return mapCouchError(err, "creating project")
	}
	return nil
}

func (r *CouchDBRepository) Update(ctx context.Context, project *Project) error {
	if err := r.db.PutDoc(ctx, project.ID, project); err != nil {
		return mapCouchError(err, "updating project")
	}
	return nil
}

func (r *CouchDBRepository) Delete(ctx context.Context, id, rev string) error {
	if err := r.db.DeleteDoc(ctx, id, rev); err != nil {
		return mapCouchError(err, "deleting project")
	}
	return nil
}

func mapCouchError(err error, operation string) error {
	switch {
	case errors.Is(err, couch.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, couch.ErrConflict):
		return ErrConflict
	default:
		return fmt.Errorf("%s: %w", operation, err)
	}
}
