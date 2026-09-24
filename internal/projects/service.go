package projects

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
)

const (
	ActionProjectCreated = "PROJECT_CREATED"
	ActionProjectUpdated = "PROJECT_UPDATED"
	ActionProjectDeleted = "PROJECT_DELETED"
)

// ProjectService is the contract exposed to HTTP handlers.
type ProjectService interface {
	List(ctx context.Context) ([]PublicProject, error)
	Get(ctx context.Context, id string) (*PublicProject, error)
	Create(ctx context.Context, input CreateInput, authorID, authorRole string) (*PublicProject, error)
	Update(ctx context.Context, id string, input UpdateInput, authorID, authorRole string) (*PublicProject, error)
	Delete(ctx context.Context, id, authorID, authorRole string) error
	IsModuleActive(ctx context.Context, projectID, moduleName string) (bool, error)
}

// Service implements project lifecycle rules.
type Service struct {
	repo      Repository
	auditRepo audit.Repository
}

// NewService creates a project service.
func NewService(repo Repository, auditRepo audit.Repository) *Service {
	return &Service{repo: repo, auditRepo: auditRepo}
}

func (s *Service) List(ctx context.Context) ([]PublicProject, error) {
	projects, err := s.repo.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing projects: %w", err)
	}
	return toPublicSlice(projects), nil
}

func (s *Service) Get(ctx context.Context, id string) (*PublicProject, error) {
	project, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return toPublic(project), nil
}

func (s *Service) Create(ctx context.Context, input CreateInput, authorID, authorRole string) (*PublicProject, error) {
	if err := validateCreate(input); err != nil {
		return nil, err
	}

	modulesConfig := ModulesConfig{Lighting: true, Audio: true, Stage: true}
	if input.ModulesConfig != nil {
		modulesConfig = *input.ModulesConfig
	}

	now := time.Now().UTC()
	project := &Project{
		ID:            fmt.Sprintf("project::%s", uuid.NewString()),
		Type:          docType,
		Name:          strings.TrimSpace(input.Name),
		Venue:         strings.TrimSpace(input.Venue),
		StartDate:     input.StartDate,
		EndDate:       input.EndDate,
		ModulesConfig: modulesConfig,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := s.repo.Create(ctx, project); err != nil {
		return nil, err
	}
	s.log(ctx, ActionProjectCreated, authorID, authorRole, project)
	return toPublic(project), nil
}

func (s *Service) Update(ctx context.Context, id string, input UpdateInput, authorID, authorRole string) (*PublicProject, error) {
	project, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}

	applyUpdate(project, input)
	if err := validateProject(project); err != nil {
		return nil, err
	}
	project.UpdatedAt = time.Now().UTC()

	if err := s.repo.Update(ctx, project); err != nil {
		return nil, err
	}
	s.log(ctx, ActionProjectUpdated, authorID, authorRole, project)
	return toPublic(project), nil
}

func (s *Service) Delete(ctx context.Context, id, authorID, authorRole string) error {
	project, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, project.ID, project.Rev); err != nil {
		return err
	}
	s.log(ctx, ActionProjectDeleted, authorID, authorRole, project)
	return nil
}

func (s *Service) IsModuleActive(ctx context.Context, projectID, moduleName string) (bool, error) {
	project, err := s.repo.FindByID(ctx, projectID)
	if err != nil {
		return false, err
	}

	switch strings.ToLower(moduleName) {
	case "lighting", "lumiere":
		return project.ModulesConfig.Lighting, nil
	case "audio", "son":
		return project.ModulesConfig.Audio, nil
	case "stage", "plateau":
		return project.ModulesConfig.Stage, nil
	default:
		return false, &ValidationError{Message: "Module inconnu."}
	}
}

func validateCreate(input CreateInput) error {
	project := &Project{
		Name:      strings.TrimSpace(input.Name),
		Venue:     strings.TrimSpace(input.Venue),
		StartDate: input.StartDate,
		EndDate:   input.EndDate,
	}
	return validateProject(project)
}

func validateProject(project *Project) error {
	if project.Name == "" {
		return &ValidationError{Message: "Le champ 'name' est requis."}
	}
	if project.Venue == "" {
		return &ValidationError{Message: "Le champ 'venue' est requis."}
	}

	start, err := time.Parse(time.DateOnly, project.StartDate)
	if err != nil {
		return &ValidationError{Message: "Le champ 'start_date' doit respecter le format YYYY-MM-DD."}
	}
	end, err := time.Parse(time.DateOnly, project.EndDate)
	if err != nil {
		return &ValidationError{Message: "Le champ 'end_date' doit respecter le format YYYY-MM-DD."}
	}
	if end.Before(start) {
		return &ValidationError{Message: "Le champ 'end_date' doit être postérieur ou égal à 'start_date'."}
	}
	return nil
}

func applyUpdate(project *Project, input UpdateInput) {
	if input.Name != nil {
		project.Name = strings.TrimSpace(*input.Name)
	}
	if input.Venue != nil {
		project.Venue = strings.TrimSpace(*input.Venue)
	}
	if input.StartDate != nil {
		project.StartDate = *input.StartDate
	}
	if input.EndDate != nil {
		project.EndDate = *input.EndDate
	}
	if input.ModulesConfig != nil {
		project.ModulesConfig = *input.ModulesConfig
	}
}

func (s *Service) log(ctx context.Context, action, authorID, authorRole string, project *Project) {
	if s.auditRepo == nil {
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"name":           project.Name,
		"modules_config": project.ModulesConfig,
	})
	_ = s.auditRepo.Log(ctx, audit.AuditEntry{
		ID:         fmt.Sprintf("audit::%s", uuid.NewString()),
		Type:       "audit",
		Action:     action,
		AuthorID:   authorID,
		AuthorRole: authorRole,
		TargetID:   project.ID,
		Payload:    payload,
		CreatedAt:  time.Now().UTC(),
	})
}
