package auth

import (
	"context"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// ModuleChecker abstracts module active-state queries for the middleware layer.
// This avoids a direct dependency on the modules package.
type ModuleChecker interface {
	IsActive(ctx context.Context, name string) (bool, error)
}

// ProjectModuleChecker resolves the active state of a module for one project.
type ProjectModuleChecker interface {
	IsModuleActive(ctx context.Context, projectID, moduleName string) (bool, error)
}

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
		c.Locals("assigned_modules", claims.AssignedModules)

		return c.Next()
	}
}

// RequireProjectModule enforces module assignment and project configuration.
// RG users can access every domain. Other users must have the target module in
// their JWT. Mutation requests are rejected while the project module is off.
func RequireProjectModule(moduleName string, checker ProjectModuleChecker) fiber.Handler {
	return func(c *fiber.Ctx) error {
		targetModule := moduleName
		if targetModule == "" {
			targetModule = c.Params("module")
		}
		role, ok := c.Locals("role").(string)
		if !ok || role == "" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
		}

		if role != RoleRG && !hasAssignedModule(c.Locals("assigned_modules"), targetModule) {
			return respondError(c, fiber.StatusForbidden, "FORBIDDEN", "Accès refusé : module non attribué.")
		}

		if !isMutation(c.Method()) {
			return c.Next()
		}

		projectID := c.Params("projectId")
		if projectID == "" {
			return respondError(c, fiber.StatusBadRequest, "VALIDATION_ERROR", "Identifiant projet manquant.")
		}
		active, err := checker.IsModuleActive(c.Context(), projectID, targetModule)
		if err != nil {
			return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Impossible de vérifier l'état du module du projet.")
		}
		if !active {
			return respondError(c, fiber.StatusForbidden, "MODULE_INACTIVE", "Ce module est inactif pour le projet. Modification refusée.")
		}
		return c.Next()
	}
}

func hasAssignedModule(value interface{}, moduleName string) bool {
	assigned, ok := value.([]string)
	if !ok {
		return false
	}
	wanted := normalizeModuleName(moduleName)
	for _, module := range assigned {
		if normalizeModuleName(module) == wanted {
			return true
		}
	}
	return false
}

func normalizeModuleName(name string) string {
	switch strings.ToLower(name) {
	case "lighting":
		return RoleLumiere
	case "audio":
		return RoleSon
	case "stage":
		return RolePlateau
	default:
		return strings.ToLower(name)
	}
}

func isMutation(method string) bool {
	switch strings.ToUpper(method) {
	case fiber.MethodPost, fiber.MethodPatch, fiber.MethodDelete:
		return true
	default:
		return false
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
// for both read and write operations.
//
// The target department is read from the ":department" URL parameter.
//   - RG: read access is always granted; write access is delegated to
//     RequireModuleActive on the relevant routes.
//   - Technicians (lumiere, son): read AND write access only on their own
//     department. Cross-department access returns 403.
//
// Must run after JWTMiddleware.
func RequireDepartment() fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, ok := c.Locals("role").(string)
		if !ok || role == "" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
		}

		// RG has unrestricted department access (write gated by RequireModuleActive).
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

// RequireModuleActive returns a middleware that blocks mutation requests
// (PATCH, POST, DELETE) when the target module is inactive in CouchDB.
//
// Technicians (lumiere, son) skip this check — their own department is always
// their responsibility. Only the RG role is subject to module-active gating.
// Must run after JWTMiddleware.
func RequireModuleActive(moduleName string, checker ModuleChecker) fiber.Handler {
	return func(c *fiber.Ctx) error {
		role, ok := c.Locals("role").(string)
		if !ok || role == "" {
			return respondError(c, fiber.StatusUnauthorized, "UNAUTHORIZED", "Authentification requise.")
		}

		// Technicians are always allowed to modify their own department.
		if role != RoleRG {
			return c.Next()
		}

		// Only gate mutation methods.
		method := strings.ToUpper(c.Method())
		if method != "PATCH" && method != "POST" && method != "DELETE" {
			return c.Next()
		}

		active, err := checker.IsActive(c.Context(), moduleName)
		if err != nil {
			return respondError(c, fiber.StatusInternalServerError, "INTERNAL_ERROR", "Impossible de vérifier l'état du module.")
		}

		if !active {
			return respondError(c, fiber.StatusForbidden, "MODULE_INACTIVE",
				"Le module '"+moduleName+"' est inactif. Modification refusée.")
		}

		return c.Next()
	}
}
