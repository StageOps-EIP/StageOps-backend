package team

import (
	"errors"

	"github.com/gofiber/fiber/v2"
)

type Handler struct {
	service TeamService
}

func NewHandler(service TeamService) *Handler {
	return &Handler{service: service}
}

func (h *Handler) List(c *fiber.Ctx) error {
	items, err := h.service.List(c.UserContext())
	if err != nil {
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Erreur lors de la récupération des membres.")
	}
	return c.Status(fiber.StatusOK).JSON(items)
}

func (h *Handler) Get(c *fiber.Ctx) error {
	item, err := h.service.Get(c.UserContext(), c.Params("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Membre introuvable.")
		}
		return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Erreur lors de la récupération du membre.")
	}
	return c.Status(fiber.StatusOK).JSON(item)
}

func (h *Handler) Create(c *fiber.Ctx) error {
	var input Input
	if err := c.BodyParser(&input); err != nil {
		return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Corps de requête invalide.")
	}

	item, err := h.service.Create(c.UserContext(), &input)
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

	item, err := h.service.Update(c.UserContext(), c.Params("id"), &input)
	if err != nil {
		return mapError(c, err)
	}
	return c.Status(fiber.StatusOK).JSON(item)
}

func (h *Handler) Delete(c *fiber.Ctx) error {
	if err := h.service.Delete(c.UserContext(), c.Params("id")); err != nil {
		return mapError(c, err)
	}
	return c.SendStatus(fiber.StatusNoContent)
}

func mapError(c *fiber.Ctx, err error) error {
	if errors.Is(err, ErrNotFound) {
		return respondError(c, fiber.StatusNotFound, "NOT_FOUND", "Membre introuvable.")
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
