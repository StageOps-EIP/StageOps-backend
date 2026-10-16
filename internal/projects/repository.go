package projects

import (
	"context"
	"errors"
	"fmt"

	"github.com/stageops/backend/internal/couch"
	"github.com/stageops/backend/internal/tenant"
)

const (
	docType       = "project"
	designDoc     = "projects"
	viewByTheatre = "by_theatre"
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
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	var projects []Project
	if err := r.db.ListByViewKey(ctx, designDoc, viewByTheatre, theatreID, &projects); err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return projects, nil
}

func (r *CouchDBRepository) FindByID(ctx context.Context, id string) (*Project, error) {
	var project Project
	if err := r.db.GetDoc(ctx, id, &project); err != nil {
		return nil, mapCouchError(err, "fetching project")
	}
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil || project.Type != docType || project.TheatreID != theatreID {
		return nil, ErrNotFound
	}
	return &project, nil
}

func (r *CouchDBRepository) Create(ctx context.Context, project *Project) error {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return err
	}
	project.TheatreID = theatreID
	if err := r.db.PutDoc(ctx, project.ID, project); err != nil {
		return mapCouchError(err, "creating project")
	}
	return nil
}

func (r *CouchDBRepository) Update(ctx context.Context, project *Project) error {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return err
	}
	if project.TheatreID != theatreID {
		return ErrNotFound
	}
	if err := r.db.PutDoc(ctx, project.ID, project); err != nil {
		return mapCouchError(err, "updating project")
	}
	return nil
}

func (r *CouchDBRepository) Delete(ctx context.Context, id, rev string) error {
	project, err := r.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if project.Rev != rev {
		return ErrConflict
	}
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
