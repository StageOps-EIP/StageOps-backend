package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

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
