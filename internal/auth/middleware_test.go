package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type projectModuleCheckerMock struct {
	active bool
	err    error
}

func (m projectModuleCheckerMock) IsModuleActive(context.Context, string, string) (bool, error) {
	return m.active, m.err
}

func newProjectModuleApp(role string, assigned []string, active bool) *fiber.App {
	app := fiber.New()
	app.All("/projects/:projectId/lighting", func(c *fiber.Ctx) error {
		c.Locals("role", role)
		c.Locals("assigned_modules", assigned)
		return c.Next()
	}, RequireProjectModule("lighting", projectModuleCheckerMock{active: active}), func(c *fiber.Ctx) error {
		return c.SendStatus(http.StatusOK)
	})
	return app
}

func TestRequireProjectModuleAllowsAssignedRead(t *testing.T) {
	app := newProjectModuleApp(RoleSon, []string{RoleLumiere}, false)

	response, _ := app.Test(httptest.NewRequest(http.MethodGet, "/projects/project::1/lighting", nil))

	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func TestRequireProjectModuleRejectsUnassignedUser(t *testing.T) {
	app := newProjectModuleApp(RoleSon, []string{RoleSon}, true)

	response, _ := app.Test(httptest.NewRequest(http.MethodGet, "/projects/project::1/lighting", nil))

	assert.Equal(t, http.StatusForbidden, response.StatusCode)
}

func TestRequireProjectModuleRejectsInactiveMutation(t *testing.T) {
	app := newProjectModuleApp(RoleLumiere, []string{RoleLumiere}, false)

	response, _ := app.Test(httptest.NewRequest(http.MethodPost, "/projects/project::1/lighting", nil))

	assert.Equal(t, http.StatusForbidden, response.StatusCode)
}

func TestRequireProjectModuleLetsRGReadAnyModule(t *testing.T) {
	app := newProjectModuleApp(RoleRG, nil, false)

	response, _ := app.Test(httptest.NewRequest(http.MethodGet, "/projects/project::1/lighting", nil))

	assert.Equal(t, http.StatusOK, response.StatusCode)
}

func newMiddlewareTestApp(secret string) *fiber.App {
	app := fiber.New()
	app.Get("/protected", JWTMiddleware(secret), func(c *fiber.Ctx) error {
		return c.Status(http.StatusOK).JSON(fiber.Map{
			"user_id": c.Locals("user_id"),
			"email":   c.Locals("email"),
			"role":    c.Locals("role"),
		})
	})
	return app
}

func TestJWTMiddleware_ValidToken(t *testing.T) {
	secret := "test-secret"
	app := newMiddlewareTestApp(secret)

	token, err := generateToken("user::abc", "user@example.com", RoleRG, secret)
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestJWTMiddleware_ExpiredToken(t *testing.T) {
	secret := "test-secret"
	app := newMiddlewareTestApp(secret)

	claims := Claims{
		UserID: "user::abc",
		Email:  "user@example.com",
		Role:   RoleRG,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, _ := tok.SignedString([]byte(secret))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+signed)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_MalformedToken(t *testing.T) {
	app := newMiddlewareTestApp("test-secret")

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not.a.valid.token")

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_MissingHeader(t *testing.T) {
	app := newMiddlewareTestApp("test-secret")

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestJWTMiddleware_WrongScheme(t *testing.T) {
	secret := "test-secret"
	app := newMiddlewareTestApp(secret)

	token, _ := generateToken("user::abc", "user@example.com", RoleRG, secret)

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Basic "+token)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- RequireRole ---

// newRequireRoleApp builds a test app with JWTMiddleware + RequireRole guarding /secure.
func newRequireRoleApp(secret string, allowedRoles ...string) *fiber.App {
	app := fiber.New()
	app.Get("/secure",
		JWTMiddleware(secret),
		RequireRole(allowedRoles...),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)
	return app
}

func TestRequireRole_RGOnRGRoute_Pass(t *testing.T) {
	secret := "test-secret"
	app := newRequireRoleApp(secret, RoleRG)

	token, _ := generateToken("user::rg", "rg@example.com", RoleRG, secret)
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireRole_LumiereOnRGRoute_Forbidden(t *testing.T) {
	secret := "test-secret"
	app := newRequireRoleApp(secret, RoleRG)

	token, _ := generateToken("user::lumiere", "lumiere@example.com", RoleLumiere, secret)
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRequireRole_NoToken_Unauthorized(t *testing.T) {
	app := newRequireRoleApp("test-secret", RoleRG)

	req := httptest.NewRequest(http.MethodGet, "/secure", nil)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

func TestRequireRole_MultipleAllowedRoles(t *testing.T) {
	secret := "test-secret"
	// Route allows lumiere and son but not plateau.
	app := newRequireRoleApp(secret, RoleLumiere, RoleSon)

	tokenSon, _ := generateToken("user::son", "son@example.com", RoleSon, secret)
	req := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req.Header.Set("Authorization", "Bearer "+tokenSon)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	tokenPlateau, _ := generateToken("user::plateau", "plateau@example.com", RolePlateau, secret)
	req2 := httptest.NewRequest(http.MethodGet, "/secure", nil)
	req2.Header.Set("Authorization", "Bearer "+tokenPlateau)
	resp2, _ := app.Test(req2)
	assert.Equal(t, http.StatusForbidden, resp2.StatusCode)
}

// --- RequireDepartment ---

// newDepartmentApp builds a test app where the role is injected via a
// preceding middleware (simulating JWTMiddleware) and RequireDepartment
// guards the route by checking the :department URL param.
func newDepartmentApp(role string) *fiber.App {
	app := fiber.New()
	app.Get("/dept/:department",
		func(c *fiber.Ctx) error {
			c.Locals("role", role)
			return c.Next()
		},
		RequireDepartment(),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)
	return app
}

func TestRequireDepartment_SonOnSon_Pass(t *testing.T) {
	app := newDepartmentApp(RoleSon)

	req := httptest.NewRequest(http.MethodGet, "/dept/son", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireDepartment_SonOnLumiere_Forbidden(t *testing.T) {
	app := newDepartmentApp(RoleSon)

	req := httptest.NewRequest(http.MethodGet, "/dept/lumiere", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRequireDepartment_RGOnAnyDept_Pass(t *testing.T) {
	for _, dept := range []string{RoleLumiere, RoleSon, RolePlateau} {
		app := newDepartmentApp(RoleRG)
		req := httptest.NewRequest(http.MethodGet, "/dept/"+dept, nil)
		resp, _ := app.Test(req)
		assert.Equal(t, http.StatusOK, resp.StatusCode, "dept=%s", dept)
	}
}

func TestRequireDepartment_NoRole_Unauthorized(t *testing.T) {
	app := fiber.New()
	app.Get("/dept/:department",
		RequireDepartment(),
		func(c *fiber.Ctx) error { return c.SendStatus(http.StatusOK) },
	)

	req := httptest.NewRequest(http.MethodGet, "/dept/son", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
}

// --- RequireModuleActive ---

// mockModuleChecker implements ModuleChecker for testing.
type mockModuleChecker struct {
	active bool
	err    error
}

func (m *mockModuleChecker) IsActive(_ context.Context, _ string) (bool, error) {
	return m.active, m.err
}

func newModuleActiveTestApp(role, moduleName string, checker ModuleChecker) *fiber.App {
	app := fiber.New()
	app.Add("PATCH", "/resource",
		func(c *fiber.Ctx) error {
			c.Locals("role", role)
			return c.Next()
		},
		RequireModuleActive(moduleName, checker),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)
	// Also register GET for read-through tests.
	app.Get("/resource",
		func(c *fiber.Ctx) error {
			c.Locals("role", role)
			return c.Next()
		},
		RequireModuleActive(moduleName, checker),
		func(c *fiber.Ctx) error {
			return c.SendStatus(http.StatusOK)
		},
	)
	return app
}

func TestRequireModuleActive_RG_ModuleActive_Pass(t *testing.T) {
	checker := &mockModuleChecker{active: true}
	app := newModuleActiveTestApp(RoleRG, "lumiere", checker)

	req := httptest.NewRequest(http.MethodPatch, "/resource", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireModuleActive_RG_ModuleInactive_Forbidden(t *testing.T) {
	checker := &mockModuleChecker{active: false}
	app := newModuleActiveTestApp(RoleRG, "lumiere", checker)

	req := httptest.NewRequest(http.MethodPatch, "/resource", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
}

func TestRequireModuleActive_TechnicienLumiere_SkipCheck(t *testing.T) {
	// Checker returns inactive, but technicien should skip this check.
	checker := &mockModuleChecker{active: false}
	app := newModuleActiveTestApp(RoleLumiere, "lumiere", checker)

	req := httptest.NewRequest(http.MethodPatch, "/resource", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireModuleActive_RG_GET_AlwaysAllowed(t *testing.T) {
	checker := &mockModuleChecker{active: false}
	app := newModuleActiveTestApp(RoleRG, "lumiere", checker)

	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestRequireModuleActive_CheckerError_InternalError(t *testing.T) {
	checker := &mockModuleChecker{err: errors.New("db down")}
	app := newModuleActiveTestApp(RoleRG, "lumiere", checker)

	req := httptest.NewRequest(http.MethodPatch, "/resource", nil)
	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
}
