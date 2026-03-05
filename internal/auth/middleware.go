package auth

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// JWTMiddleware validates the Bearer token from the Authorization header.
// On success it sets "user_id", "email", and "role" in fiber.Ctx locals.
func JWTMiddleware(secret string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		header := c.Get("Authorization")
		if header == "" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
		}

		parts := strings.SplitN(header, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Format d'autorisation invalide.")
		}

		claims, err := validateToken(parts[1], secret)
		if err != nil {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Token invalide ou expiré.")
		}

		c.Locals("user_id", claims.UserID)
		c.Locals("email", claims.Email)
		c.Locals("role", claims.Role)

		return c.Next()
	}
}

// RequireRole returns a middleware that allows only requests whose JWT role
// is listed in the allowed set. It must run after JWTMiddleware.
// Returns 403 Forbidden for any other valid role, 401 if role is absent.
func RequireRole(roles ...string) fiber.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(c *fiber.Ctx) error {
		role, ok := c.Locals("role").(string)
		if !ok || role == "" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
		}

		if !allowed[role] {
			return respondError(c, fiber.StatusForbidden, "FORBIDDEN", "Accès refusé : droits insuffisants.")
		}

		return c.Next()
	}
}

// RequireDepartment returns a middleware that enforces department-scoped access
// for material updates and incident reports.
//
// The target department is read from the ":department" URL parameter.
// RG passes unconditionally. Technicians are only allowed to act on the
// department that matches their own role. Returns 403 otherwise.
// Must run after JWTMiddleware.
func RequireDepartment() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, ok := c.Locals("role").(string)
		if !ok || role == "" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
		}

		// RG has unrestricted department access.
		if role == RoleRG {
			return c.Next()
		}

		dept := c.Params("department")
		if dept == "" {
			return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Département cible non spécifié.")
		}

		if dept != role {
			return respondError(c, fiber.StatusForbidden, "FORBIDDEN", "Accès refusé : ce département ne correspond pas à votre rôle.")
		}

		return c.Next()
	}
}
