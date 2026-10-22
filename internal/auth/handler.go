package auth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

// Handler exposes the auth HTTP endpoints.
type Handler struct {
	service AuthService
}

// NewHandler creates a Handler backed by the given AuthService.
func NewHandler(service AuthService) *Handler {
	return &Handler{service: service}
}

// Register handles POST /api/auth/register.
func (h *Handler) Register(c *fiber.Ctx) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := parseJSONBody(c, &body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	tokens, err := h.service.Register(c.UserContext(), body.Email, body.Password)
	if err != nil {
		return mapServiceError(c, err)
	}

	if tokens == nil {
		return c.Status(fiber.StatusCreated).JSON(fiber.Map{"status": "verification_required"})
	}
	return c.Status(fiber.StatusCreated).JSON(tokens)
}

// Login handles POST /api/auth/login.
func (h *Handler) Login(c *fiber.Ctx) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := parseJSONBody(c, &body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	tokens, err := h.service.Login(c.UserContext(), body.Email, body.Password)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(tokens)
}

// Refresh handles POST /api/auth/refresh and rotates the supplied refresh token.
func (h *Handler) Refresh(c *fiber.Ctx) error {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := parseJSONBody(c, &body); err != nil || body.RefreshToken == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Le refresh token est requis.")
	}
	tokens, err := h.service.Refresh(c.UserContext(), body.RefreshToken)
	if err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(tokens)
}

// Logout handles POST /api/auth/logout and revokes one refresh-token family.
func (h *Handler) Logout(c *fiber.Ctx) error {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := parseJSONBody(c, &body); err != nil || body.RefreshToken == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Le refresh token est requis.")
	}
	if err := h.service.Logout(c.UserContext(), body.RefreshToken); err != nil {
		return mapServiceError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// LogoutAll handles POST /api/auth/logout-all for the authenticated user.
func (h *Handler) LogoutAll(c *fiber.Ctx) error {
	userID := localValue(c, "user_id")
	if userID == "" {
		return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
	}
	if err := h.service.LogoutAll(c.UserContext(), userID); err != nil {
		return mapServiceError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// VerifyEmail handles POST /api/auth/verify-email.
func (h *Handler) VerifyEmail(c *fiber.Ctx) error {
	var body struct {
		Token string `json:"token"`
	}
	if err := parseJSONBody(c, &body); err != nil || body.Token == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Le token de vérification est requis.")
	}
	tokens, err := h.service.VerifyEmail(c.UserContext(), body.Token)
	if err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(tokens)
}

// ResendVerification handles POST /api/auth/resend-verification.
func (h *Handler) ResendVerification(c *fiber.Ctx) error {
	var body struct {
		Email string `json:"email"`
	}
	if err := parseJSONBody(c, &body); err != nil || body.Email == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "L'adresse email est requise.")
	}
	if err := h.service.ResendVerification(c.UserContext(), body.Email); err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
		"status": "verification_sent_if_account_exists",
	})
}

// JWKS exposes the public offline-grant verification key.
func (h *Handler) JWKS(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(h.service.OfflineJWKS())
}

// CreateOfflineGrant handles POST /api/auth/offline-grants.
func (h *Handler) CreateOfflineGrant(c *fiber.Ctx) error {
	var body struct {
		Name string `json:"name"`
	}
	if err := parseJSONBody(c, &body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	grant, err := h.service.CreateOfflineGrant(c.UserContext(), localValue(c, "user_id"), body.Name)
	if err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(grant)
}

// ListDevices handles GET /api/auth/devices.
func (h *Handler) ListDevices(c *fiber.Ctx) error {
	devices, err := h.service.ListDevices(c.UserContext(), localValue(c, "user_id"))
	if err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(devices)
}

// RevokeDevice handles DELETE /api/auth/devices/:id.
func (h *Handler) RevokeDevice(c *fiber.Ctx) error {
	if err := h.service.RevokeDevice(c.UserContext(), localValue(c, "user_id"), c.Params("id")); err != nil {
		return mapServiceError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

// Me handles GET /api/auth/me (protected by JWTMiddleware).
func (h *Handler) Me(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
	}

	user, err := h.service.GetUser(c.UserContext(), userID)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(user)
}

// ListUsers handles GET /api/users?limit=&offset=.
// Protected by JWTMiddleware + RequireRole(RoleRG).
func (h *Handler) ListUsers(c *fiber.Ctx) error {
	limit, err := queryInt(c, "limit")
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Le paramètre 'limit' doit être un entier.")
	}
	offset, err := queryInt(c, "offset")
	if err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Le paramètre 'offset' doit être un entier.")
	}

	users, err := h.service.ListUsers(c.UserContext(), UserPage{Limit: limit, Offset: offset})
	if err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(users)
}

func queryInt(c *fiber.Ctx, key string) (int, error) {
	raw := c.Query(key)
	if raw == "" {
		return 0, nil
	}
	return strconv.Atoi(raw)
}

// UpdateUserRole handles PATCH /api/users/:id/role.
// Protected by JWTMiddleware + RequireRole(RoleRG).
func (h *Handler) UpdateUserRole(c *fiber.Ctx) error {
	targetID := c.Params("id")
	if targetID == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Identifiant utilisateur manquant.")
	}

	var body struct {
		Role string `json:"role"`
	}
	if err := parseJSONBody(c, &body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	authorID, _ := c.Locals("user_id").(string)
	authorRole, _ := c.Locals("role").(string)

	updated, err := h.service.UpdateUserRole(c.UserContext(), targetID, body.Role, authorID, authorRole)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(updated)
}

// UpdateUserModules handles PATCH /api/users/:id/modules.
func (h *Handler) UpdateUserModules(c *fiber.Ctx) error {
	targetID := c.Params("id")
	if targetID == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Identifiant utilisateur manquant.")
	}
	var body struct {
		AssignedModules *[]string `json:"assigned_modules"`
	}
	if err := parseJSONBody(c, &body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	if body.AssignedModules == nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Le champ 'assigned_modules' est requis.")
	}
	updated, err := h.service.UpdateUserModules(
		c.UserContext(), targetID, *body.AssignedModules,
		localValue(c, "user_id"), localValue(c, "role"),
	)
	if err != nil {
		return mapServiceError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(updated)
}

func localValue(c *fiber.Ctx, key string) string {
	value, _ := c.Locals(key).(string)
	return value
}

func parseJSONBody(c *fiber.Ctx, destination interface{}) error {
	if len(c.Body()) == 0 || len(c.Body()) > 16*1024 {
		return errors.New("invalid JSON body size")
	}
	decoder := json.NewDecoder(bytes.NewReader(c.Body()))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

// respondError writes the standard error JSON envelope.
func respondError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    code,
			"message": message,
		},
	})
}

func respondValidationError(c *fiber.Ctx, validationError *ValidationError) error {
	payload := fiber.Map{
		"code":    "VALIDATION_ERROR",
		"message": validationError.Message,
	}
	if len(validationError.Fields) > 0 {
		payload["fields"] = validationError.Fields
	}
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": payload})
}

// mapServiceError translates domain errors into appropriate HTTP responses.
func mapServiceError(c *fiber.Ctx, err error) error {
	var validErr *ValidationError
	switch {
	case errors.As(err, &validErr):
		return respondValidationError(c, validErr)
	case errors.Is(err, ErrEmailAlreadyExists):
		return respondError(c, fiber.StatusConflict, "EMAIL_ALREADY_EXISTS", "Un compte avec cet email existe déjà.")
	case errors.Is(err, ErrInvalidCredentials):
		return respondError(c, fiber.StatusUnauthorized, "INVALID_CREDENTIALS", "Identifiants incorrects.")
	case errors.Is(err, ErrAccountLocked):
		return respondError(c, fiber.StatusTooManyRequests, "ACCOUNT_LOCKED", "Compte temporairement bloqué suite à plusieurs tentatives échouées. Réessayez dans 15 minutes.")
	case errors.Is(err, ErrForbidden):
		return respondError(c, fiber.StatusForbidden, "FORBIDDEN", "Accès refusé pour ce théâtre.")
	case errors.Is(err, ErrInvalidRefresh):
		return respondError(c, fiber.StatusUnauthorized, "INVALID_REFRESH_TOKEN", "Session invalide ou expirée.")
	case errors.Is(err, ErrEmailNotVerified):
		return respondError(c, fiber.StatusForbidden, "EMAIL_NOT_VERIFIED", "Confirmez votre adresse email avant de vous connecter.")
	case errors.Is(err, ErrInvalidVerification):
		return respondError(c, fiber.StatusBadRequest, "INVALID_VERIFICATION_TOKEN", "Lien de vérification invalide ou expiré.")
	case errors.Is(err, ErrUserNotFound):
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Utilisateur non trouvé.")
	case errors.Is(err, ErrDeviceNotFound):
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Appareil non trouvé.")
	default:
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
	}
}
