package incidents

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type serviceMock struct {
	createFn func(context.Context, string, string, Input, string, string) (*Incident, error)
}

func (m *serviceMock) List(context.Context, string, string) ([]Incident, error) {
	return []Incident{}, nil
}

func (m *serviceMock) Get(context.Context, string, string, string) (*Incident, error) {
	return nil, ErrNotFound
}

func (m *serviceMock) Create(ctx context.Context, projectID, module string, input Input, authorID, authorRole string) (*Incident, error) {
	return m.createFn(ctx, projectID, module, input, authorID, authorRole)
}

func (m *serviceMock) Update(context.Context, string, string, string, Input, string, string) (*Incident, error) {
	return nil, ErrNotFound
}

func (m *serviceMock) Delete(context.Context, string, string, string, string, string) error {
	return nil
}

func TestHandlerCreate(t *testing.T) {
	service := &serviceMock{createFn: func(_ context.Context, projectID, module string, input Input, authorID, authorRole string) (*Incident, error) {
		assert.Equal(t, "project::1", projectID)
		assert.Equal(t, "lighting", module)
		assert.Equal(t, "user::1", authorID)
		return &Incident{ID: "incident::1", Title: input.Title}, nil
	}}
	app := fiber.New()
	app.Post("/projects/:projectId/incidents/:module", identity(), NewHandler(service).Create)
	req := httptest.NewRequest("POST", "/projects/project::1/incidents/lighting", strings.NewReader(`{"title":"Panne","description":"Spot HS","severity":"high"}`))
	req.Header.Set("Content-Type", "application/json")

	response, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusCreated, response.StatusCode)
}

func TestHandlerCreateMapsValidationError(t *testing.T) {
	service := &serviceMock{createFn: func(context.Context, string, string, Input, string, string) (*Incident, error) {
		return nil, ErrInvalidSeverity
	}}
	app := fiber.New()
	app.Post("/projects/:projectId/incidents/:module", NewHandler(service).Create)
	req := httptest.NewRequest("POST", "/projects/project::1/incidents/lighting", strings.NewReader(`{"title":"Panne"}`))
	req.Header.Set("Content-Type", "application/json")

	response, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)
}

func TestHandlerCreateRejectsMalformedBody(t *testing.T) {
	service := &serviceMock{createFn: func(context.Context, string, string, Input, string, string) (*Incident, error) {
		t.Fatal("service must not be called")
		return nil, nil
	}}
	app := fiber.New()
	app.Post("/projects/:projectId/incidents/:module", NewHandler(service).Create)
	req := httptest.NewRequest("POST", "/projects/project::1/incidents/lighting", strings.NewReader(`{"title":`))
	req.Header.Set("Content-Type", "application/json")

	response, err := app.Test(req)

	require.NoError(t, err)
	assert.Equal(t, fiber.StatusBadRequest, response.StatusCode)
}

func identity() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Locals("user_id", "user::1")
		c.Locals("role", "lumiere")
		return c.Next()
	}
}
