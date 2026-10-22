package incidents

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/tenant"
)

type IncidentService interface {
	List(ctx context.Context, projectID, module string, filter ListFilter) ([]Incident, error)
	Get(ctx context.Context, projectID, module, id string) (*Incident, error)
	Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Incident, error)
	Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Incident, error)
	Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error
}

// ProjectCalendar exposes the inclusive operating dates of a project.
type ProjectCalendar interface {
	DateRange(ctx context.Context, projectID string) (time.Time, time.Time, error)
}

// EquipmentLinker gives incidents access to the equipment they report on.
type EquipmentLinker interface {
	Exists(ctx context.Context, projectID, module, id string) (bool, error)
	ApplyIncidentState(ctx context.Context, projectID, module, id string, hadActive, hasActive bool, authorID, authorRole string) error
}

// ListFilter narrows a listing. Date (YYYY-MM-DD) keeps only the incidents
// declared for that operating day.
type ListFilter struct {
	Date string
}

type Service struct {
	repo      Repository
	auditRepo audit.Repository
	calendar  ProjectCalendar
	equipment EquipmentLinker
}

func NewService(repo Repository, auditRepo audit.Repository, calendar ProjectCalendar, equipment EquipmentLinker) *Service {
	return &Service{repo: repo, auditRepo: auditRepo, calendar: calendar, equipment: equipment}
}

func (s *Service) List(ctx context.Context, projectID, module string, filter ListFilter) ([]Incident, error) {
	if err := validateScope(projectID, module); err != nil {
		return nil, err
	}
	if filter.Date != "" {
		if err := validateDay("date", filter.Date); err != nil {
			return nil, err
		}
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]doc, 0)
	for _, incident := range docs {
		if incident.ProjectID == projectID && incident.Module == module && (filter.Date == "" || incident.day() == filter.Date) {
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
	now := time.Now().UTC()
	if input.Date == "" {
		input.Date = now.Format(time.DateOnly)
	}
	if err := validateInput(projectID, module, input); err != nil {
		return nil, err
	}
	if err := s.validateDate(ctx, projectID, input.Date); err != nil {
		return nil, err
	}
	if err := s.validateEquipment(ctx, projectID, module, input.EquipmentID); err != nil {
		return nil, err
	}
	if input.Status == "" {
		input.Status = "open"
	}
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	before, err := s.linkedIncidents(ctx, projectID, module, input.EquipmentID)
	if err != nil {
		return nil, err
	}
	incident := &doc{
		ID: fmt.Sprintf("incident::%s", uuid.NewString()), Type: docType,
		TheatreID: theatreID,
		ProjectID: projectID, Module: module, Title: strings.TrimSpace(input.Title),
		Description: input.Description, Severity: input.Severity, Status: input.Status,
		EquipmentID: input.EquipmentID, Date: input.Date, ReportedBy: authorID, ResolvedAt: input.ResolvedAt,
		ResolutionNotes: input.ResolutionNotes, Images: emptyIfNil(input.Images), CreatedAt: now, UpdatedAt: now,
	}
	applyResolution(incident, now)
	if err := s.repo.Create(ctx, incident); err != nil {
		return nil, err
	}
	s.log(ctx, audit.ActionIncidentReported, authorID, authorRole, incident)
	s.syncEquipment(ctx, projectID, module, before, withDoc(before, incident), authorID, authorRole, incident.EquipmentID)
	return toPublic(incident), nil
}

func (s *Service) Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Incident, error) {
	incident, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return nil, err
	}
	if input.Date == "" {
		input.Date = incident.day()
	}
	if err := validateInput(projectID, module, input); err != nil {
		return nil, err
	}
	if err := s.validateDate(ctx, projectID, input.Date); err != nil {
		return nil, err
	}
	// An unchanged link stays valid even if the equipment was deleted since.
	if input.EquipmentID != incident.EquipmentID {
		if err := s.validateEquipment(ctx, projectID, module, input.EquipmentID); err != nil {
			return nil, err
		}
	}
	if input.Status == "" {
		input.Status = "open"
	}
	previousEquipmentID := incident.EquipmentID
	before, err := s.linkedIncidents(ctx, projectID, module, previousEquipmentID, input.EquipmentID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	incident.Title, incident.Description = strings.TrimSpace(input.Title), input.Description
	incident.Severity, incident.Status, incident.EquipmentID = input.Severity, input.Status, input.EquipmentID
	incident.Date, incident.ResolvedAt, incident.ResolutionNotes = input.Date, input.ResolvedAt, input.ResolutionNotes
	incident.Images, incident.UpdatedAt = emptyIfNil(input.Images), now
	applyResolution(incident, now)
	if err := s.repo.Update(ctx, incident); err != nil {
		return nil, err
	}
	s.log(ctx, "INCIDENT_UPDATED", authorID, authorRole, incident)
	s.syncEquipment(ctx, projectID, module, before, withDoc(before, incident), authorID, authorRole, previousEquipmentID, incident.EquipmentID)
	return toPublic(incident), nil
}

func (s *Service) Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error {
	incident, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return err
	}
	before, err := s.linkedIncidents(ctx, projectID, module, incident.EquipmentID)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, incident.ID, incident.Rev); err != nil {
		return err
	}
	s.log(ctx, "INCIDENT_DELETED", authorID, authorRole, incident)
	s.syncEquipment(ctx, projectID, module, before, withoutDoc(before, incident.ID), authorID, authorRole, incident.EquipmentID)
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

// validateDate checks that the operating date falls within the project dates.
func (s *Service) validateDate(ctx context.Context, projectID, day string) error {
	if s.calendar == nil {
		return nil
	}
	start, end, err := s.calendar.DateRange(ctx, projectID)
	if err != nil {
		return fmt.Errorf("reading project dates: %w", err)
	}
	if day < start.Format(time.DateOnly) || day > end.Format(time.DateOnly) {
		return &ValidationError{Message: "Le champ 'date' doit être compris dans les dates du projet."}
	}
	return nil
}

// validateEquipment checks that a linked equipment belongs to the same project and module.
func (s *Service) validateEquipment(ctx context.Context, projectID, module, equipmentID string) error {
	if equipmentID == "" || s.equipment == nil {
		return nil
	}
	exists, err := s.equipment.Exists(ctx, projectID, module, equipmentID)
	if err != nil {
		return fmt.Errorf("checking linked equipment: %w", err)
	}
	if !exists {
		return &ValidationError{Message: "L'équipement lié est introuvable dans ce projet et ce module."}
	}
	return nil
}

// linkedIncidents returns the incidents of the scope when at least one of the
// equipment ids is set, so that equipment statuses can be reconciled.
func (s *Service) linkedIncidents(ctx context.Context, projectID, module string, equipmentIDs ...string) ([]doc, error) {
	if s.equipment == nil || !anyNonEmpty(equipmentIDs) {
		return nil, nil
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	scoped := make([]doc, 0, len(docs))
	for _, incident := range docs {
		if incident.ProjectID == projectID && incident.Module == module {
			scoped = append(scoped, incident)
		}
	}
	return scoped, nil
}

// syncEquipment is best effort: the incident is already stored, so a failure
// to update the equipment status is logged instead of failing the request.
func (s *Service) syncEquipment(ctx context.Context, projectID, module string, before, after []doc, authorID, authorRole string, equipmentIDs ...string) {
	if s.equipment == nil {
		return
	}
	seen := map[string]bool{}
	for _, id := range equipmentIDs {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		hadActive, hasActive := hasActiveIncident(before, id), hasActiveIncident(after, id)
		if err := s.equipment.ApplyIncidentState(ctx, projectID, module, id, hadActive, hasActive, authorID, authorRole); err != nil {
			log.Printf("incidents: updating status of equipment %s: %v", id, err)
		}
	}
}

func hasActiveIncident(docs []doc, equipmentID string) bool {
	for _, incident := range docs {
		if incident.EquipmentID == equipmentID && isActive(incident.Status) {
			return true
		}
	}
	return false
}

func withDoc(docs []doc, incident *doc) []doc {
	return append(withoutDoc(docs, incident.ID), *incident)
}

func withoutDoc(docs []doc, id string) []doc {
	result := make([]doc, 0, len(docs)+1)
	for _, existing := range docs {
		if existing.ID != id {
			result = append(result, existing)
		}
	}
	return result
}

func anyNonEmpty(values []string) bool {
	for _, value := range values {
		if value != "" {
			return true
		}
	}
	return false
}

// applyResolution keeps resolved_at consistent with the status: it is set when
// an incident is resolved or closed and cleared when it is reopened.
func applyResolution(incident *doc, now time.Time) {
	if isActive(incident.Status) {
		incident.ResolvedAt = nil
		return
	}
	if incident.ResolvedAt == nil {
		incident.ResolvedAt = &now
	}
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
	if input.Date != "" {
		if err := validateDay("date", input.Date); err != nil {
			return err
		}
	}
	return nil
}

func validateDay(field, value string) error {
	if _, err := time.Parse(time.DateOnly, value); err != nil {
		return &ValidationError{Message: fmt.Sprintf("Le champ '%s' doit respecter le format YYYY-MM-DD.", field)}
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
