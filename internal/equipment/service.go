package equipment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/tenant"
)

type EquipmentService interface {
	List(ctx context.Context, projectID, module string, filter ListFilter) ([]Equipment, error)
	Get(ctx context.Context, projectID, module, id string) (*Equipment, error)
	Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Equipment, error)
	Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Equipment, error)
	Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error
}

// ProjectCalendar exposes the inclusive operating dates of a project.
type ProjectCalendar interface {
	DateRange(ctx context.Context, projectID string) (time.Time, time.Time, error)
}

// ListFilter narrows a listing. Date (YYYY-MM-DD) keeps only the equipment
// visible on that day: inside the project dates and its own availability window.
type ListFilter struct {
	Date string
}

type Service struct {
	repo      Repository
	auditRepo audit.Repository
	calendar  ProjectCalendar
}

func NewService(repo Repository, auditRepo audit.Repository, calendar ProjectCalendar) *Service {
	return &Service{repo: repo, auditRepo: auditRepo, calendar: calendar}
}

func (s *Service) List(ctx context.Context, projectID, module string, filter ListFilter) ([]Equipment, error) {
	if err := validateScope(projectID, module); err != nil {
		return nil, err
	}
	day := ""
	if filter.Date != "" {
		if _, err := parseDay("date", filter.Date); err != nil {
			return nil, err
		}
		inProject, err := s.withinProject(ctx, projectID, filter.Date)
		if err != nil {
			return nil, err
		}
		if !inProject {
			return []Equipment{}, nil
		}
		day = filter.Date
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]doc, 0)
	for _, item := range docs {
		if item.ProjectID == projectID && item.Module == module && (day == "" || item.visibleOn(day)) {
			filtered = append(filtered, item)
		}
	}
	return toPublicSlice(filtered), nil
}

// visibleOn compares YYYY-MM-DD strings, whose lexical order is chronological.
func (d doc) visibleOn(day string) bool {
	return (d.AvailableFrom == "" || d.AvailableFrom <= day) && (d.AvailableTo == "" || day <= d.AvailableTo)
}

func (s *Service) Get(ctx context.Context, projectID, module, id string) (*Equipment, error) {
	item, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return nil, err
	}
	return toPublic(item), nil
}

func (s *Service) Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Equipment, error) {
	if err := validateInput(projectID, module, &input); err != nil {
		return nil, err
	}
	if err := s.validateAvailability(ctx, projectID, input); err != nil {
		return nil, err
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateUniqueness(docs, "", projectID, module, input); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return nil, err
	}
	if input.Status == "" {
		input.Status = "ok"
	}
	if input.LastCheck == nil {
		input.LastCheck = &now
	}
	if input.Position == nil {
		// New items appear at the stage origin until they are placed in 2D/3D.
		input.Position = &Position{}
	}
	item := &doc{
		ID: fmt.Sprintf("equipment::%s", uuid.NewString()), Type: docType,
		TheatreID: theatreID,
		ProjectID: projectID, Module: module, Name: strings.TrimSpace(input.Name), Kind: input.Kind,
		QRCode: input.QRCode, Status: input.Status, Location: input.Location, Zone: input.Zone,
		ResponsiblePerson: input.ResponsiblePerson, LastCheck: input.LastCheck, Position: input.Position,
		AvailableFrom: input.AvailableFrom, AvailableTo: input.AvailableTo,
		DMXUniverse: input.DMXUniverse, DMXAddress: input.DMXAddress, DMXChannels: input.DMXChannels,
		Notes: input.Notes, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.repo.Create(ctx, item); err != nil {
		return nil, err
	}
	s.log(ctx, "EQUIPMENT_CREATED", authorID, authorRole, item)
	return toPublic(item), nil
}

func (s *Service) Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Equipment, error) {
	if err := validateInput(projectID, module, &input); err != nil {
		return nil, err
	}
	if err := s.validateAvailability(ctx, projectID, input); err != nil {
		return nil, err
	}
	current, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return nil, err
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateUniqueness(docs, id, projectID, module, input); err != nil {
		return nil, err
	}
	if input.Status == "" {
		input.Status = "ok"
	}
	if input.Position == nil {
		input.Position = current.Position
	}
	current.Name, current.Kind, current.QRCode = strings.TrimSpace(input.Name), input.Kind, input.QRCode
	current.Status, current.Location, current.Zone = input.Status, input.Location, input.Zone
	current.ResponsiblePerson, current.LastCheck, current.Position = input.ResponsiblePerson, input.LastCheck, input.Position
	current.AvailableFrom, current.AvailableTo = input.AvailableFrom, input.AvailableTo
	current.DMXUniverse, current.DMXAddress, current.DMXChannels = input.DMXUniverse, input.DMXAddress, input.DMXChannels
	current.Notes, current.UpdatedAt = input.Notes, time.Now().UTC()
	if err := s.repo.Update(ctx, current); err != nil {
		return nil, err
	}
	s.log(ctx, audit.ActionMaterialUpdated, authorID, authorRole, current)
	return toPublic(current), nil
}

func (s *Service) Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error {
	current, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return err
	}
	if err := s.repo.Delete(ctx, current.ID, current.Rev); err != nil {
		return err
	}
	s.log(ctx, "EQUIPMENT_DELETED", authorID, authorRole, current)
	return nil
}

// Exists reports whether an equipment item belongs to the given project and module.
func (s *Service) Exists(ctx context.Context, projectID, module, id string) (bool, error) {
	_, err := s.findInScope(ctx, projectID, module, id)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// ApplyIncidentState keeps the equipment status consistent with its incidents,
// with the same rule as the web workspace: an active incident moves an "ok" item
// to "to-check", and the item is "ok" again once its last active incident ends.
// Items marked "hs" or "repair" by a technician are never changed automatically.
func (s *Service) ApplyIncidentState(ctx context.Context, projectID, module, id string, hadActive, hasActive bool, authorID, authorRole string) error {
	current, err := s.findInScope(ctx, projectID, module, id)
	if err != nil {
		return err
	}
	next := current.Status
	switch {
	case current.Status == "hs" || current.Status == "repair":
	case hasActive && current.Status == "ok":
		next = "to-check"
	case !hasActive && hadActive && current.Status == "to-check":
		next = "ok"
	}
	if next == current.Status {
		return nil
	}
	current.Status, current.UpdatedAt = next, time.Now().UTC()
	if err := s.repo.Update(ctx, current); err != nil {
		return err
	}
	s.log(ctx, audit.ActionMaterialUpdated, authorID, authorRole, current)
	return nil
}

func (s *Service) withinProject(ctx context.Context, projectID string, days ...string) (bool, error) {
	if s.calendar == nil {
		return true, nil
	}
	start, end, err := s.calendar.DateRange(ctx, projectID)
	if err != nil {
		return false, fmt.Errorf("reading project dates: %w", err)
	}
	first, last := start.Format(time.DateOnly), end.Format(time.DateOnly)
	for _, day := range days {
		if day != "" && (day < first || day > last) {
			return false, nil
		}
	}
	return true, nil
}

func (s *Service) validateAvailability(ctx context.Context, projectID string, input Input) error {
	if input.AvailableFrom == "" && input.AvailableTo == "" {
		return nil
	}
	inProject, err := s.withinProject(ctx, projectID, input.AvailableFrom, input.AvailableTo)
	if err != nil {
		return err
	}
	if !inProject {
		return &ValidationError{Message: "La période de disponibilité doit rester comprise dans les dates du projet."}
	}
	return nil
}

func (s *Service) findInScope(ctx context.Context, projectID, module, id string) (*doc, error) {
	if err := validateScope(projectID, module); err != nil {
		return nil, err
	}
	item, err := s.repo.FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if item.ProjectID != projectID || item.Module != module {
		return nil, ErrNotFound
	}
	return item, nil
}

func validateInput(projectID, module string, input *Input) error {
	if err := validateScope(projectID, module); err != nil {
		return err
	}
	if strings.TrimSpace(input.Name) == "" {
		return &ValidationError{Message: "Le champ 'name' est requis."}
	}
	if !validKinds[module][input.Kind] {
		return ErrInvalidKind
	}
	if input.Status != "" && !validStatuses[input.Status] {
		return ErrInvalidStatus
	}
	if err := validateAvailabilityWindow(input.AvailableFrom, input.AvailableTo); err != nil {
		return err
	}
	if input.DMXUniverse != nil || input.DMXAddress != nil || input.DMXChannels != 0 {
		if module != "lighting" {
			return &ValidationError{Message: "L'adressage DMX est réservé au module lighting."}
		}
		if input.DMXUniverse == nil || input.DMXAddress == nil {
			return &ValidationError{Message: "Les champs 'dmx_universe' et 'dmx_address' sont requis ensemble."}
		}
		if *input.DMXUniverse < 0 || *input.DMXAddress < 1 || *input.DMXAddress > 512 {
			return &ValidationError{Message: "Adresse DMX invalide."}
		}
		if input.DMXChannels == 0 {
			input.DMXChannels = 1
		}
		if input.DMXChannels < 1 || *input.DMXAddress+input.DMXChannels-1 > 512 {
			return &ValidationError{Message: "La plage DMX doit rester comprise entre 1 et 512."}
		}
	}
	return nil
}

func validateAvailabilityWindow(from, to string) error {
	if from != "" {
		if _, err := parseDay("available_from", from); err != nil {
			return err
		}
	}
	if to != "" {
		if _, err := parseDay("available_to", to); err != nil {
			return err
		}
	}
	if from != "" && to != "" && to < from {
		return &ValidationError{Message: "Le champ 'available_to' doit être postérieur ou égal à 'available_from'."}
	}
	return nil
}

func parseDay(field, value string) (time.Time, error) {
	day, err := time.Parse(time.DateOnly, value)
	if err != nil {
		return time.Time{}, &ValidationError{Message: fmt.Sprintf("Le champ '%s' doit respecter le format YYYY-MM-DD.", field)}
	}
	return day, nil
}

func validateScope(projectID, module string) error {
	if projectID == "" {
		return &ValidationError{Message: "Identifiant projet manquant."}
	}
	if _, ok := validKinds[module]; !ok {
		return ErrInvalidModule
	}
	return nil
}

func validateUniqueness(docs []doc, currentID, projectID, module string, input Input) error {
	for _, existing := range docs {
		if existing.ID == currentID || existing.ProjectID != projectID || existing.Module != module {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(existing.Name), strings.TrimSpace(input.Name)) {
			return ErrDuplicateName
		}
		if overlapsDMX(existing, input) {
			return ErrDMXConflict
		}
	}
	return nil
}

func overlapsDMX(existing doc, input Input) bool {
	if existing.DMXUniverse == nil || existing.DMXAddress == nil || input.DMXUniverse == nil || input.DMXAddress == nil {
		return false
	}
	if *existing.DMXUniverse != *input.DMXUniverse {
		return false
	}
	existingChannels := existing.DMXChannels
	if existingChannels < 1 {
		existingChannels = 1
	}
	inputChannels := input.DMXChannels
	if inputChannels < 1 {
		inputChannels = 1
	}
	existingEnd := *existing.DMXAddress + existingChannels - 1
	inputEnd := *input.DMXAddress + inputChannels - 1
	return *input.DMXAddress <= existingEnd && *existing.DMXAddress <= inputEnd
}

func (s *Service) log(ctx context.Context, action, authorID, authorRole string, item *doc) {
	if s.auditRepo == nil {
		return
	}
	payload, _ := json.Marshal(map[string]interface{}{"project_id": item.ProjectID, "module": item.Module, "name": item.Name})
	_ = s.auditRepo.Log(ctx, audit.AuditEntry{
		ID: fmt.Sprintf("audit::%s", uuid.NewString()), Type: "audit", Action: action,
		AuthorID: authorID, AuthorRole: authorRole, TargetID: item.ID, Payload: payload, CreatedAt: time.Now().UTC(),
	})
}
