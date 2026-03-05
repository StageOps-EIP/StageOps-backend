package auth

import (
	"errors"

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
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	token, err := h.service.Register(c.Context(), body.Email, body.Password)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"token": token})
}

// Login handles POST /api/auth/login.
func (h *Handler) Login(c *fiber.Ctx) error {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	token, err := h.service.Login(c.Context(), body.Email, body.Password)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(fiber.Map{"token": token})
}

// Me handles GET /api/auth/me (protected by JWTMiddleware).
func (h *Handler) Me(c *fiber.Ctx) error {
	userID, ok := c.Locals("user_id").(string)
	if !ok || userID == "" {
		return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
	}

	user, err := h.service.GetUser(c.Context(), userID)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(user)
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
	if err := c.BodyParser(&body); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	authorID, _ := c.Locals("user_id").(string)
	authorRole, _ := c.Locals("role").(string)

	updated, err := h.service.UpdateUserRole(c.Context(), targetID, body.Role, authorID, authorRole)
	if err != nil {
		return mapServiceError(c, err)
	}

	return c.Status(fiber.StatusOK).JSON(updated)
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

// mapServiceError translates domain errors into appropriate HTTP responses.
func mapServiceError(c *fiber.Ctx, err error) error {
	var validErr *ValidationError
	switch {
	case errors.As(err, &validErr):
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", validErr.Message)
	case errors.Is(err, ErrEmailAlreadyExists):
		return respondError(c, fiber.StatusConflict, "EMAIL_ALREADY_EXISTS", "Un compte avec cet email existe déjà.")
	case errors.Is(err, ErrInvalidCredentials):
		return respondError(c, fiber.StatusUnauthorized, "INVALID_CREDENTIALS", "Identifiants incorrects.")
	case errors.Is(err, ErrAccountLocked):
		return respondError(c, fiber.StatusTooManyRequests, "ACCOUNT_LOCKED", "Compte temporairement bloqué suite à plusieurs tentatives échouées. Réessayez dans 15 minutes.")
	case errors.Is(err, ErrUserNotFound):
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Utilisateur non trouvé.")
	default:
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
	}
}
