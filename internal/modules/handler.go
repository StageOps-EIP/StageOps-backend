package modules

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

// Handler exposes the module management HTTP endpoints.
type Handler struct {
	service ModuleService
}

// NewHandler creates a Handler backed by the given ModuleService.
func NewHandler(service ModuleService) *Handler {
	return &Handler{service: service}
}

// GetAll handles GET /api/modules.
func (h *Handler) GetAll(c *fiber.Ctx) error {
	mods, err := h.service.GetAll(c.Context())
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
	}

	return c.Status(fiber.StatusOK).JSON(mods)
}

// Toggle handles PATCH /api/modules/:name/toggle.
func (h *Handler) Toggle(c *fiber.Ctx) error {
	name := c.Params("name")
	if name == "" {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Nom de module manquant.")
	}

	authorID, _ := c.Locals("user_id").(string)
	authorRole, _ := c.Locals("role").(string)

	mod, err := h.service.Toggle(c.Context(), name, authorID, authorRole)
	if err != nil {
		if errors.Is(err, ErrModuleNotFound) {
			return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Module non trouvé.")
		}
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
	}

	return c.Status(fiber.StatusOK).JSON(mod)
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
