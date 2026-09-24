package equipment

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
)

type EquipmentService interface {
	List(ctx context.Context, projectID, module string) ([]Equipment, error)
	Get(ctx context.Context, projectID, module, id string) (*Equipment, error)
	Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Equipment, error)
	Update(ctx context.Context, projectID, module, id string, input Input, authorID, authorRole string) (*Equipment, error)
	Delete(ctx context.Context, projectID, module, id, authorID, authorRole string) error
}

type Service struct {
	repo      Repository
	auditRepo audit.Repository
}

func NewService(repo Repository, auditRepo audit.Repository) *Service {
	return &Service{repo: repo, auditRepo: auditRepo}
}

func (s *Service) List(ctx context.Context, projectID, module string) ([]Equipment, error) {
	if err := validateScope(projectID, module); err != nil {
		return nil, err
	}
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]doc, 0)
	for _, item := range docs {
		if item.ProjectID == projectID && item.Module == module {
			filtered = append(filtered, item)
		}
	}
	return toPublicSlice(filtered), nil
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
	docs, err := s.repo.List(ctx)
	if err != nil {
		return nil, err
	}
	if err := validateUniqueness(docs, "", projectID, module, input); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	if input.Status == "" {
		input.Status = "ok"
	}
	if input.LastCheck == nil {
		input.LastCheck = &now
	}
	item := &doc{
		ID: fmt.Sprintf("equipment::%s", uuid.NewString()), Type: docType,
		ProjectID: projectID, Module: module, Name: strings.TrimSpace(input.Name), Kind: input.Kind,
		QRCode: input.QRCode, Status: input.Status, Location: input.Location, Zone: input.Zone,
		ResponsiblePerson: input.ResponsiblePerson, LastCheck: input.LastCheck, Position: input.Position,
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
	current.Name, current.Kind, current.QRCode = strings.TrimSpace(input.Name), input.Kind, input.QRCode
	current.Status, current.Location, current.Zone = input.Status, input.Location, input.Zone
	current.ResponsiblePerson, current.LastCheck, current.Position = input.ResponsiblePerson, input.LastCheck, input.Position
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
