package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
)

type IncidentService interface {
	List(ctx context.Context, projectID, module string) ([]Incident, error)
	Get(ctx context.Context, projectID, module, id string) (*Incident, error)
	Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Incident, error)
	Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Incident, error)
	Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error
}

type Service struct {
	repo      Repository
	auditRepo audit.Repository
}

func NewService(repo Repository, auditRepo audit.Repository) *Service {
	return &Service{repo: repo, auditRepo: auditRepo}
}

func (s *Service) List(ctx context.Context, projectID, module string) ([]Incident, error) {
	if err := validateScope(projectID, module); err != nil {
		return nil, err
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]doc, 0)
	for _, incident := range docs {
		if incident.ProjectID == projectID && incident.Module == module {
			filtered = append(filtered, incident)
		}
	}
	return toPublicSlice(filtered), nil
}

func (s *Service) Get(ctx context.Context, projectID, module, id string) (*Incident, error) {
	incident, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return nil, err
	}
	return toPublic(incident), nil
}

func (s *Service) Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Incident, error) {
	if err := validateInput(projectID, module, input); err != nil {
		return nil, err
	}
	if input.Status == "" {
		input.Status = "open"
	}
	now := time.Now().UTC()
	incident := &doc{
		ID: fmt.Sprintf("incident::%s", uuid.NewString()), Type: docType,
		ProjectID: projectID, Module: module, Title: strings.TrimSpace(input.Title),
		Description: input.Description, Severity: input.Severity, Status: input.Status,
		EquipmentID: input.EquipmentID, ReportedBy: authorID, ResolvedAt: input.ResolvedAt,
		ResolutionNotes: input.ResolutionNotes, Images: emptyIfNil(input.Images), CreatedAt: now, UpdatedAt: now,
	}
	if err := s.repo.Create(ctx, incident); err != nil {
		return nil, err
	}
	s.log(ctx, audit.ActionIncidentReported, authorID, authorRole, incident)
	return toPublic(incident), nil
}

func (s *Service) Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Incident, error) {
	if err := validateInput(projectID, module, input); err != nil {
		return nil, err
	}
	incident, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return nil, err
	}
	if input.Status == "" {
		input.Status = "open"
	}
	incident.Title, incident.Description = strings.TrimSpace(input.Title), input.Description
	incident.Severity, incident.Status, incident.EquipmentID = input.Severity, input.Status, input.EquipmentID
	incident.ResolvedAt, incident.ResolutionNotes = input.ResolvedAt, input.ResolutionNotes
	incident.Images, incident.UpdatedAt = emptyIfNil(input.Images), time.Now().UTC()
	if incident.Status == "resolved" && incident.ResolvedAt == nil {
		now := time.Now().UTC()
		incident.ResolvedAt = &now
	}
	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}
	s.log(ctx, "INCIDENT_UPDATED", authorID, authorRole, incident)
	return toPublic(incident), nil
}

func (s *Service) Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error {
	incident, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, incident.ID, incident.Rev); err != nil {
		return err
	}
	s.log(ctx, "INCIDENT_DELETED", authorID, authorRole, incident)
	return nil
}

func (s *Service) findInScope(ctx context.Context, projectID, module, id string) (*doc, error) {
	if err := validateScope(projectID, module); err != nil {
		return nil, err
	}
	incident, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if incident.ProjectID != projectID || incident.Module != module {
		return nil, ErrNotFound
	}
	return incident, nil
}

func validateScope(projectID, module string) error {
	if projectID == "" {
		return &ValidationError{Message: "Identifiant projet manquant."}
	}
	if module != "lighting" && module != "audio" {
		return ErrInvalidModule
	}
	return nil
}

func validateInput(projectID, module string, input Input) error {
	if err := validateScope(projectID, module); err != nil {
		return err
	}
	if strings.TrimSpace(input.Title) == "" {
		return &ValidationError{Message: "Le champ 'title' est requis."}
	}
	if strings.TrimSpace(input.Description) == "" {
		return &ValidationError{Message: "Le champ 'description' est requis."}
	}
	if !validSeverities[input.Severity] {
		return ErrInvalidSeverity
	}
	if input.Status != "" && !validStatuses[input.Status] {
		return ErrInvalidStatus
	}
	return nil
}

func emptyIfNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func (s *Service) log(ctx context.Context, action, authorID, authorRole string, incident *doc) {
	if s.auditRepo == nil {
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"project_id": incident.ProjectID, "module": incident.Module,
		"severity": incident.Severity, "status": incident.Status,
	})
	_ = s.auditRepo.Log(ctx, audit.AuditEntry{
		ID: fmt.Sprintf("audit::%s", uuid.NewString()), Type: "audit", Action: action,
		AuthorID: authorID, AuthorRole: authorRole, TargetID: incident.ID, Payload: payload, CreatedAt: time.Now().UTC(),
	})
}
