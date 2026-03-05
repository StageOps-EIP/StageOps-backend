package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// --- Mock service ---

type mockAuthService struct {
	mock.Mock
}

func (m *mockAuthService) Register(ctx context.Context, email, password string) (string, error) {
	args := m.Called(ctx, email, password)
	return args.String(0), args.Error(1)
}

func (m *mockAuthService) Login(ctx context.Context, email, password string) (string, error) {
	args := m.Called(ctx, email, password)
	return args.String(0), args.Error(1)
}

func (m *mockAuthService) GetUser(ctx context.Context, id string) (*UserPublic, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserPublic), args.Error(1)
}

func (m *mockAuthService) UpdateUserRole(ctx context.Context, targetID, newRole, authorID, authorRole string) (*UserPublic, error) {
	args := m.Called(ctx, targetID, newRole, authorID, authorRole)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*UserPublic), args.Error(1)
}

// --- Helpers ---

func newTestApp(svc AuthService, jwtSecret string) *fiber.App {
	app := fiber.New(fiber.Config{ErrorHandler: func(c *fiber.Ctx, err error) error {
		return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
	}})

	h := NewHandler(svc)
	api := app.Group("/api")
	authGroup := api.Group("/auth")
	authGroup.Post("/register", h.Register)
	authGroup.Post("/login", h.Login)
	authGroup.Get("/me", JWTMiddleware(jwtSecret), h.Me)

	usersGroup := api.Group("/users", JWTMiddleware(jwtSecret))
	usersGroup.Patch("/:id/role", RequireRole(RoleRG), h.UpdateUserRole)

	return app
}

func postJSON(app *fiber.App, path string, body interface{}) *http.Response {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := app.Test(req)
	return resp
}

func patchJSON(app *fiber.App, path string, body interface{}, token string) *http.Response {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPatch, path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, _ := app.Test(req)
	return resp
}

func decodeError(resp *http.Response) map[string]interface{} {
	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result["error"].(map[string]interface{})
}

// --- Register ---

func TestRegisterHandler_Success(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	svc.On("Register", mock.Anything, "user@example.com", "SecurePass1!").
		Return("jwt.token.here", nil)

	resp := postJSON(app, "/api/auth/register", map[string]string{
		"email":    "user@example.com",
		"password": "SecurePass1!",
	})

	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, "jwt.token.here", result["token"])
	svc.AssertExpectations(t)
}

func TestRegisterHandler_EmailAlreadyExists(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	svc.On("Register", mock.Anything, "taken@example.com", "SecurePass1!").
		Return("", ErrEmailAlreadyExists)

	resp := postJSON(app, "/api/auth/register", map[string]string{
		"email":    "taken@example.com",
		"password": "SecurePass1!",
	})

	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "EMAIL_ALREADY_EXISTS", errObj["code"])
	svc.AssertExpectations(t)
}

func TestRegisterHandler_ValidationError(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	svc.On("Register", mock.Anything, "bad-email", "weak").
		Return("", &ValidationError{Message: "Format d'email invalide."})

	resp := postJSON(app, "/api/auth/register", map[string]string{
		"email":    "bad-email",
		"password": "weak",
	})

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "VALIDATION_ERROR", errObj["code"])
	assert.Equal(t, "Format d'email invalide.", errObj["message"])
	svc.AssertExpectations(t)
}

// --- Login ---

func TestLoginHandler_Success(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	svc.On("Login", mock.Anything, "user@example.com", "SecurePass1!").
		Return("jwt.token.here", nil)

	resp := postJSON(app, "/api/auth/login", map[string]string{
		"email":    "user@example.com",
		"password": "SecurePass1!",
	})

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]string
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, "jwt.token.here", result["token"])
	svc.AssertExpectations(t)
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	svc.On("Login", mock.Anything, "user@example.com", "WrongPass1!").
		Return("", ErrInvalidCredentials)

	resp := postJSON(app, "/api/auth/login", map[string]string{
		"email":    "user@example.com",
		"password": "WrongPass1!",
	})

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "INVALID_CREDENTIALS", errObj["code"])
	svc.AssertExpectations(t)
}

func TestLoginHandler_AccountLocked(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	svc.On("Login", mock.Anything, "locked@example.com", "SecurePass1!").
		Return("", ErrAccountLocked)

	resp := postJSON(app, "/api/auth/login", map[string]string{
		"email":    "locked@example.com",
		"password": "SecurePass1!",
	})

	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "ACCOUNT_LOCKED", errObj["code"])
	svc.AssertExpectations(t)
}

func TestLoginHandler_UnknownEmail(t *testing.T) {
	svc := new(mockAuthService)
	app := newTestApp(svc, "test-secret")

	// Service maps unknown email to ErrInvalidCredentials to avoid info leak.
	svc.On("Login", mock.Anything, "ghost@example.com", "SecurePass1!").
		Return("", ErrInvalidCredentials)

	resp := postJSON(app, "/api/auth/login", map[string]string{
		"email":    "ghost@example.com",
		"password": "SecurePass1!",
	})

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	svc.AssertExpectations(t)
}

// --- Me ---

func TestMeHandler_Success(t *testing.T) {
	svc := new(mockAuthService)
	jwtSecret := "test-secret"
	app := newTestApp(svc, jwtSecret)

	user := &UserPublic{
		ID:        "user::abc",
		Email:     "user@example.com",
		Role:      RolePlateau,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	svc.On("GetUser", mock.Anything, "user::abc").Return(user, nil)

	token, _ := generateToken("user::abc", "user@example.com", RolePlateau, jwtSecret)
	req := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, _ := app.Test(req)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result UserPublic
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, "user::abc", result.ID)
	assert.Equal(t, "user@example.com", result.Email)
	svc.AssertExpectations(t)
}

// --- PATCH /api/users/:id/role ---

func TestUpdateUserRoleHandler_Success(t *testing.T) {
	svc := new(mockAuthService)
	jwtSecret := "test-secret"
	app := newTestApp(svc, jwtSecret)

	updated := &UserPublic{
		ID:        "user::target",
		Email:     "target@example.com",
		Role:      RoleSon,
		CreatedAt: time.Now().UTC().Truncate(time.Second),
	}
	svc.On("UpdateUserRole", mock.Anything, "user::target", RoleSon, "user::rg", RoleRG).
		Return(updated, nil)

	token, _ := generateToken("user::rg", "rg@example.com", RoleRG, jwtSecret)
	resp := patchJSON(app, "/api/users/user::target/role", map[string]string{"role": RoleSon}, token)

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	var result UserPublic
	json.NewDecoder(resp.Body).Decode(&result)
	assert.Equal(t, RoleSon, result.Role)
	svc.AssertExpectations(t)
}

func TestUpdateUserRoleHandler_Forbidden_Lumiere(t *testing.T) {
	svc := new(mockAuthService)
	jwtSecret := "test-secret"
	app := newTestApp(svc, jwtSecret)

	token, _ := generateToken("user::lumiere", "lumiere@example.com", RoleLumiere, jwtSecret)
	resp := patchJSON(app, "/api/users/user::target/role", map[string]string{"role": RoleRG}, token)

	assert.Equal(t, http.StatusForbidden, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "FORBIDDEN", errObj["code"])
	// Service must not be called.
	svc.AssertNotCalled(t, "UpdateUserRole")
}

func TestUpdateUserRoleHandler_InvalidRole(t *testing.T) {
	svc := new(mockAuthService)
	jwtSecret := "test-secret"
	app := newTestApp(svc, jwtSecret)

	svc.On("UpdateUserRole", mock.Anything, "user::target", "superadmin", "user::rg", RoleRG).
		Return(nil, &ValidationError{Message: `Rôle invalide : "superadmin". Valeurs acceptées : rg, lumiere, son, plateau.`})

	token, _ := generateToken("user::rg", "rg@example.com", RoleRG, jwtSecret)
	resp := patchJSON(app, "/api/users/user::target/role", map[string]string{"role": "superadmin"}, token)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "VALIDATION_ERROR", errObj["code"])
	svc.AssertExpectations(t)
}

func TestUpdateUserRoleHandler_NotFound(t *testing.T) {
	svc := new(mockAuthService)
	jwtSecret := "test-secret"
	app := newTestApp(svc, jwtSecret)

	svc.On("UpdateUserRole", mock.Anything, "user::ghost", RoleSon, "user::rg", RoleRG).
		Return(nil, ErrUserNotFound)

	token, _ := generateToken("user::rg", "rg@example.com", RoleRG, jwtSecret)
	resp := patchJSON(app, "/api/users/user::ghost/role", map[string]string{"role": RoleSon}, token)

	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	errObj := decodeError(resp)
	assert.Equal(t, "NOT_FOUND", errObj["code"])
	svc.AssertExpectations(t)
}
