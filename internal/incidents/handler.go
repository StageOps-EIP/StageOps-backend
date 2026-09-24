package incidents

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

type Handler struct{ service IncidentService }

func NewHandler(service IncidentService) *Handler { return &Handler{service: service} }

func (h *Handler) List(c *fiber.Ctx) error {
	incidents, err := h.service.List(c.Context(), c.Params("projectId"), c.Params("module"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(incidents)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	incident, err := h.service.Get(c.Context(), c.Params("projectId"), c.Params("module"), c.Params("id"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(incident)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var input Input
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	incident, err := h.service.Create(c.Context(), c.Params("projectId"), c.Params("module"), input, local(c, "user_id"), local(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(incident)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	var input Input
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	incident, err := h.service.Update(c.Context(), c.Params("projectId"), c.Params("module"), c.Params("id"), input, local(c, "user_id"), local(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(incident)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	err := h.service.Delete(c.Context(), c.Params("projectId"), c.Params("module"), c.Params("id"), local(c, "user_id"), local(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func local(c *fiber.Ctx, key string) string {
	value, _ := c.Locals(key).(string)
	return value
}

func mapError(c *fiber.Ctx, err error) error {
	switch {
	case errors.Is(err, ErrNotFound):
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Incident introuvable.")
	case errors.Is(err, ErrConflict):
		return respondError(c, fiber.StatusConflict, "CONFLICT", "L'incident a été modifié par une autre requête.")
	case errors.Is(err, ErrInvalidStatus):
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Statut invalide. Valeurs acceptées : open, in-progress, resolved, closed.")
	case errors.Is(err, ErrInvalidSeverity):
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Sévérité invalide. Valeurs acceptées : low, medium, high, critical.")
	case errors.Is(err, ErrInvalidModule):
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Module invalide. Valeurs acceptées : lighting, audio.")
	}
	var validationError *ValidationError
	if errors.As(err, &validationError) {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", validationError.Message)
	}
	return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
}

func respondError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{"error": fiber.Map{"code": code, "message": message}})
}
