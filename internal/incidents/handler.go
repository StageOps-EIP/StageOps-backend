package incidents

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	repo *Repository
}

func NewHandler(repo *Repository) *Handler {
	return &Handler{repo: repo}
}

func (h *Handler) List(c *fiber.Ctx) error {
	items, err := h.repo.List(c.Context())
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Erreur lors de la récupération des incidents.")
	}
	return c.Status(fiber.StatusOK).JSON(items)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	item, err := h.repo.FindByID(c.Context(), c.Params("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Incident introuvable.")
		}
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Erreur lors de la récupération de l'incident.")
	}
	return c.Status(fiber.StatusOK).JSON(item)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var input Input
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	item, err := h.repo.Create(c.Context(), &input)
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

	item, err := h.repo.Update(c.Context(), c.Params("id"), &input)
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(item)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	if err := h.repo.Delete(c.Context(), c.Params("id")); err != nil {
		return mapError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func mapError(c *fiber.Ctx, err error) error {
	if errors.Is(err, ErrNotFound) {
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Incident introuvable.")
	}
	if errors.Is(err, ErrInvalidStatus) {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Statut invalide. Valeurs acceptées : open, in-progress, resolved, closed.")
	}
	if errors.Is(err, ErrInvalidSeverity) {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Sévérité invalide. Valeurs acceptées : low, medium, high, critical.")
	}
	var valErr *ValidationError
	if errors.As(err, &valErr) {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", valErr.Message)
	}
	return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Une erreur interne est survenue.")
}

func respondError(c *fiber.Ctx, status int, code, message string) error {
	return c.Status(status).JSON(fiber.Map{
		"error": fiber.Map{"code": code, "message": message},
	})
}
