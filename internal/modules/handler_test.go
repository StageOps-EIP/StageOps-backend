package modules

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock service ---

type mockService struct {
	mock.Mock
}

func (m *mockService) GetAll(ctx context.Context) ([]ModulePublic, error) {
	args := m.Called(ctx)
	mods, _ := args.Get(0).([]ModulePublic)
	return mods, args.Error(1)
}

func (m *mockService) Toggle(ctx context.Context, name, authorID, authorRole string) (*ModulePublic, error) {
	args := m.Called(ctx, name, authorID, authorRole)
	mod, _ := args.Get(0).(*ModulePublic)
	return mod, args.Error(1)
}

func (m *mockService) IsActive(ctx context.Context, name string) (bool, error) {
	args := m.Called(ctx, name)
	return args.Bool(0), args.Error(1)
}

// --- Handler tests ---

func TestHandler_GetAll_Success(t *testing.T) {
	svc := new(mockService)
	h := NewHandler(svc)

	svc.On("GetAll", mock.Anything).Return([]ModulePublic{
		{Name: "lumiere", Active: true},
		{Name: "son", Active: false},
	}, nil)

	app := fiber.New()
	app.Get("/modules", h.GetAll)

	req := httptest.NewRequest(http.MethodGet, "/modules", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var body []ModulePublic
	json.NewDecoder(resp.Body).Decode(&body)
	assert.Len(t, body, 2)
}

func TestHandler_GetAll_Error(t *testing.T) {
	svc := new(mockService)
	h := NewHandler(svc)

	svc.On("GetAll", mock.Anything).Return(nil, errors.New("db error"))

	app := fiber.New()
	app.Get("/modules", h.GetAll)

	req := httptest.NewRequest(http.MethodGet, "/modules", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}

func TestHandler_Toggle_Success(t *testing.T) {
	svc := new(mockService)
	h := NewHandler(svc)

	svc.On("Toggle", mock.Anything, "lumiere", "user::rg1", "rg").Return(&ModulePublic{
		Name:   "lumiere",
		Active: false,
	}, nil)

	app := fiber.New()
	app.Patch("/modules/:name/toggle", func(c *fiber.Ctx) error {
		c.Locals("user_id", "user::rg1")
		c.Locals("role", "rg")
		return c.Next()
	}, h.Toggle)

	req := httptest.NewRequest(http.MethodPatch, "/modules/lumiere/toggle", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestHandler_Toggle_NotFound(t *testing.T) {
	svc := new(mockService)
	h := NewHandler(svc)

	svc.On("Toggle", mock.Anything, "inexistant", "", "").Return(nil, ErrModuleNotFound)

	app := fiber.New()
	app.Patch("/modules/:name/toggle", h.Toggle)

	req := httptest.NewRequest(http.MethodPatch, "/modules/inexistant/toggle", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestHandler_Toggle_InternalError(t *testing.T) {
	svc := new(mockService)
	h := NewHandler(svc)

	svc.On("Toggle", mock.Anything, "lumiere", "", "").Return(nil, errors.New("conflict"))

	app := fiber.New()
	app.Patch("/modules/:name/toggle", h.Toggle)

	req := httptest.NewRequest(http.MethodPatch, "/modules/lumiere/toggle", nil)
	resp, err := app.Test(req)

	assert.NoError(t, err)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
