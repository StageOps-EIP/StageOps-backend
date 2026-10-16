package modules

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/tenant"
)

// validModuleNames lists the module names accepted by the system.
var validModuleNames = map[string]bool{
	"lumiere": true,
	"son":     true,
	"plateau": true,
}

// IsValidModuleName reports whether name is a recognized module.
func IsValidModuleName(name string) bool {
	return validModuleNames[name]
}

// ModuleService is the interface exposed to HTTP handlers.
type ModuleService interface {
	GetAll(ctx context.Context) ([]ModulePublic, error)
	Toggle(ctx context.Context, name, authorID, authorRole string) (*ModulePublic, error)
	IsActive(ctx context.Context, name string) (bool, error)
}

// Service implements ModuleService.
type Service struct {
	repo      Repository
	cache     *Cache
	auditRepo audit.Repository
}

// NewService creates a new modules Service.
func NewService(repo Repository, cache *Cache, auditRepo audit.Repository) *Service {
	return &Service{repo: repo, cache: cache, auditRepo: auditRepo}
}

// GetAll returns the public representation of all modules.
func (s *Service) GetAll(ctx context.Context) ([]ModulePublic, error) {
	mods, err := s.repo.GetAll(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetching modules: %w", err)
	}

	result := make([]ModulePublic, 0, len(mods))
	for _, m := range mods {
		result = append(result, ModulePublic{
			Name:      m.Name,
			Active:    m.Active,
			UpdatedAt: m.UpdatedAt,
		})
	}

	return result, nil
}

// Toggle flips the active state of a module and logs the action in audit.
func (s *Service) Toggle(ctx context.Context, name, authorID, authorRole string) (*ModulePublic, error) {
	if !IsValidModuleName(name) {
		return nil, ErrModuleNotFound
	}
	cacheKey, err := moduleCacheKey(ctx, name)
	if err != nil {
		return nil, err
	}

	mod, err := s.repo.Toggle(ctx, name)
	if err != nil {
		return nil, err
	}

	// Invalidate cache so the next middleware check picks up the new state.
	s.cache.Invalidate(cacheKey)

	s.logModuleToggle(ctx, authorID, authorRole, name, mod.Active)

	return &ModulePublic{
		Name:      mod.Name,
		Active:    mod.Active,
		UpdatedAt: mod.UpdatedAt,
	}, nil
}

// IsActive checks whether a module is active, using the cache first.
func (s *Service) IsActive(ctx context.Context, name string) (bool, error) {
	cacheKey, err := moduleCacheKey(ctx, name)
	if err != nil {
		return false, err
	}
	if active, ok := s.cache.Get(cacheKey); ok {
		return active, nil
	}

	mod, err := s.repo.GetByName(ctx, name)
	if err != nil {
		return false, err
	}

	s.cache.Set(cacheKey, mod.Active)
	return mod.Active, nil
}

func moduleCacheKey(ctx context.Context, name string) (string, error) {
	theatreID, err := tenant.RequireTheatreID(ctx)
	if err != nil {
		return "", err
	}
	return theatreID + "::" + name, nil
}

// logModuleToggle writes a MODULE_TOGGLED audit entry. Failures are swallowed
// so that an audit error never blocks the toggle operation.
func (s *Service) logModuleToggle(ctx context.Context, authorID, authorRole, moduleName string, newState bool) {
	if s.auditRepo == nil {
		return
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"module": moduleName,
		"active": newState,
	})

	entry := audit.AuditEntry{
		ID:         fmt.Sprintf("audit::%s", uuid.New().String()),
		Type:       "audit",
		Action:     ActionModuleToggled,
		AuthorID:   authorID,
		AuthorRole: authorRole,
		TargetID:   fmt.Sprintf("module::%s::%s", theatreIDFromContext(ctx), moduleName),
		Payload:    payload,
		CreatedAt:  time.Now().UTC(),
	}

	_ = s.auditRepo.Log(ctx, entry)
}

func theatreIDFromContext(ctx context.Context) string {
	theatreID, _ := tenant.TheatreID(ctx)
	return theatreID
}

// ActionModuleToggled is the audit log action for module state changes.
const ActionModuleToggled = "MODULE_TOGGLED"
