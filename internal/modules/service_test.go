package modules

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock repository ---

type mockRepository struct {
	mock.Mock
}

func (m *mockRepository) GetByName(ctx context.Context, name string) (*Module, error) {
	args := m.Called(ctx, name)
	mod, _ := args.Get(0).(*Module)
	return mod, args.Error(1)
}

func (m *mockRepository) Toggle(ctx context.Context, name string) (*Module, error) {
	args := m.Called(ctx, name)
	mod, _ := args.Get(0).(*Module)
	return mod, args.Error(1)
}

func (m *mockRepository) GetAll(ctx context.Context) ([]Module, error) {
	args := m.Called(ctx)
	mods, _ := args.Get(0).([]Module)
	return mods, args.Error(1)
}

// --- Mock audit repository ---

type mockAuditRepo struct {
	mock.Mock
}

func (m *mockAuditRepo) Log(ctx context.Context, entry interface{}) error {
	args := m.Called(ctx, entry)
	return args.Error(0)
}

// --- Tests ---

func TestService_GetAll_Success(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	repo.On("GetAll", mock.Anything).Return([]Module{
		{Name: "lumiere", Active: true},
		{Name: "son", Active: false},
	}, nil)

	result, err := svc.GetAll(context.Background())

	assert.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, "lumiere", result[0].Name)
	assert.True(t, result[0].Active)
	assert.Equal(t, "son", result[1].Name)
	assert.False(t, result[1].Active)
}

func TestService_GetAll_Error(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	repo.On("GetAll", mock.Anything).Return(nil, errors.New("db error"))

	_, err := svc.GetAll(context.Background())
	assert.Error(t, err)
}

func TestService_Toggle_Success(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	// Pre-populate cache to verify invalidation.
	cache.Set("lumiere", true)

	repo.On("Toggle", mock.Anything, "lumiere").Return(&Module{
		Name:   "lumiere",
		Active: false,
	}, nil)

	result, err := svc.Toggle(context.Background(), "lumiere", "user::rg1", "rg")

	assert.NoError(t, err)
	assert.Equal(t, "lumiere", result.Name)
	assert.False(t, result.Active)

	// Cache must be invalidated.
	_, ok := cache.Get("lumiere")
	assert.False(t, ok, "cache should be invalidated after toggle")
}

func TestService_Toggle_InvalidName(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	_, err := svc.Toggle(context.Background(), "invalid", "user::rg1", "rg")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrModuleNotFound))
}

func TestService_Toggle_NotFound(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	repo.On("Toggle", mock.Anything, "lumiere").Return(nil, ErrModuleNotFound)

	_, err := svc.Toggle(context.Background(), "lumiere", "user::rg1", "rg")

	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrModuleNotFound))
}

func TestService_IsActive_CacheHit(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	cache.Set("lumiere", true)

	active, err := svc.IsActive(context.Background(), "lumiere")

	assert.NoError(t, err)
	assert.True(t, active)
	// Repository should not be called.
	repo.AssertNotCalled(t, "GetByName")
}

func TestService_IsActive_CacheMiss(t *testing.T) {
	repo := new(mockRepository)
	cache := NewCache()
	svc := NewService(repo, cache, nil)

	repo.On("GetByName", mock.Anything, "son").Return(&Module{
		Name:   "son",
		Active: false,
	}, nil)

	active, err := svc.IsActive(context.Background(), "son")

	assert.NoError(t, err)
	assert.False(t, active)

	// Value should now be cached.
	cached, ok := cache.Get("son")
	assert.True(t, ok)
	assert.False(t, cached)
}
