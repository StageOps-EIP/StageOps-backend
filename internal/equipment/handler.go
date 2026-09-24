package equipment

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

type Handler struct{ service EquipmentService }

func NewHandler(service EquipmentService) *Handler { return &Handler{service: service} }

func (h *Handler) List(c *fiber.Ctx) error {
	items, err := h.service.List(c.Context(), c.Params("projectId"), c.Params("module"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(items)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	item, err := h.service.Get(c.Context(), c.Params("projectId"), c.Params("module"), c.Params("id"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(item)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var input Input
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	item, err := h.service.Create(c.Context(), c.Params("projectId"), c.Params("module"), input, local(c, "user_id"), local(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusCreated).JSON(item)
}

func (h *Handler) Update(c *fiber.Ctx) error {
	var input Input
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}
	item, err := h.service.Update(c.Context(), c.Params("projectId"), c.Params("module"), c.Params("id"), input, local(c, "user_id"), local(c, "role"))
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(item)
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
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Équipement introuvable.")
	case errors.Is(err, ErrConflict):
		return respondError(c, fiber.StatusConflict, "CONFLICT", "L'équipement a été modifié par une autre requête.")
	case errors.Is(err, ErrDMXConflict):
		return respondError(c, fiber.StatusConflict, "DMX_CONFLICT", "Cette plage DMX chevauche un équipement existant.")
	case errors.Is(err, ErrDuplicateName):
		return respondError(c, fiber.StatusConflict, "DUPLICATE_NAME", "Un équipement porte déjà ce nom dans ce module.")
	case errors.Is(err, ErrInvalidStatus):
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Statut invalide. Valeurs acceptées : ok, to-check, hs, repair.")
	case errors.Is(err, ErrInvalidModule), errors.Is(err, ErrInvalidKind):
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Module ou type d'équipement invalide.")
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
