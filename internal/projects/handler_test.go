package projects

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type serviceMock struct {
	listFn   func(context.Context) ([]PublicProject, error)
	getFn    func(context.Context, string) (*PublicProject, error)
	createFn func(context.Context, CreateInput, string, string) (*PublicProject, error)
	updateFn func(context.Context, string, UpdateInput, string, string) (*PublicProject, error)
	deleteFn func(context.Context, string, string, string) error
}

func (m *serviceMock) List(ctx context.Context) ([]PublicProject, error) {
	return m.listFn(ctx)
}

func (m *serviceMock) Get(ctx context.Context, id string) (*PublicProject, error) {
	return m.getFn(ctx, id)
}

func (m *serviceMock) Create(ctx context.Context, input CreateInput, userID, role string) (*PublicProject, error) {
	return m.createFn(ctx, input, userID, role)
}

func (m *serviceMock) Update(ctx context.Context, id string, input UpdateInput, userID, role string) (*PublicProject, error) {
	return m.updateFn(ctx, id, input, userID, role)
}

func (m *serviceMock) Delete(ctx context.Context, id, userID, role string) error {
	return m.deleteFn(ctx, id, userID, role)
}

func (m *serviceMock) IsModuleActive(context.Context, string, string) (bool, error) {
	return false, nil
}

func TestHandlerCreate(t *testing.T) {
	service := &serviceMock{createFn: func(_ context.Context, input CreateInput, userID, role string) (*PublicProject, error) {
		assert.Equal(t, "Festival", input.Name)
		assert.Equal(t, "user::1", userID)
		assert.Equal(t, "rg", role)
		return &PublicProject{ID: "project::1", Name: input.Name}, nil
	}}
	app := fiber.New()
	handler := NewHandler(service)
	app.Post("/projects", withIdentity(), handler.Create)
	req := httptest.NewRequest("POST", "/projects", strings.NewReader(`{"name":"Festival","venue":"Arena","start_date":"2027-06-10","end_date":"2027-06-12"}`))
	req.Header.Set("Content-Type", "application/json")

	response, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, response.StatusCode)
}

func TestHandlerGetMapsNotFound(t *testing.T) {
	service := &serviceMock{getFn: func(context.Context, string) (*PublicProject, error) {
		return nil, ErrNotFound
	}}
	app := fiber.New()
	app.Get("/projects/:id", NewHandler(service).Get)

	response, err := app.Test(httptest.NewRequest("GET", "/projects/project::missing", nil))

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNotFound, response.StatusCode)
}

func TestHandlerUpdateRejectsMalformedBody(t *testing.T) {
	service := &serviceMock{updateFn: func(context.Context, string, UpdateInput, string, string) (*PublicProject, error) {
		return nil, errors.New("must not be called")
	}}
	app := fiber.New()
	app.Patch("/projects/:id", NewHandler(service).Update)
	req := httptest.NewRequest("PATCH", "/projects/project::1", strings.NewReader(`{"name":`))
	req.Header.Set("Content-Type", "application/json")

	response, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)
}

func TestHandlerDelete(t *testing.T) {
	service := &serviceMock{deleteFn: func(_ context.Context, id, userID, role string) error {
		assert.Equal(t, "project::1", id)
		assert.Equal(t, "user::1", userID)
		assert.Equal(t, "rg", role)
		return nil
	}}
	app := fiber.New()
	app.Delete("/projects/:id", withIdentity(), NewHandler(service).Delete)

	response, err := app.Test(httptest.NewRequest("DELETE", "/projects/project::1", nil))

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusNoContent, response.StatusCode)
}

func withIdentity() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals("user_id", "user::1")
		c.Locals("role", "rg")
		return c.Next()
	}
}
