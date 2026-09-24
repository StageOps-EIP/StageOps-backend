package projects

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

// Handler exposes project lifecycle endpoints.
type Handler struct {
	service ProjectService
}

// NewHandler creates a project HTTP handler.
func NewHandler(service ProjectService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) List(c *fiber.Ctx) error {
	projects, err := h.service.List(c.Context())
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Erreur lors de la récupération des projets.")
	}
	return c.Status(fiber.StatusOK).JSON(projects)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	project, err := h.service.Get(c.Context(), c.Params("id"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(project)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var input CreateInput
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	project, err := h.service.Create(c.Context(), input, localString(c, "user_id"), localString(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(project)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	var input UpdateInput
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	project, err := h.service.Update(c.Context(), c.Params("id"), input, localString(c, "user_id"), localString(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(project)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	err := h.service.Delete(c.Context(), c.Params("id"), localString(c, "user_id"), localString(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func localString(c *fiber.Ctx, key string) string {
	value, _ := c.Locals(key).(string)
	return value
}

func mapError(c *fiber.Ctx, err error) error {
	if errors.Is(err, ErrNotFound) {
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Projet introuvable.")
	}
	if errors.Is(err, ErrConflict) {
		return respondError(c, fiber.StatusConflict, "CONFLICT", "Le projet a été modifié par une autre requête.")
	}
	var validationError *ValidationError
	if errors.As(err, &validationError) {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", validationError.Message)
	}
	return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
}

func respondError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{"code": code, "message": message},
	})
}
