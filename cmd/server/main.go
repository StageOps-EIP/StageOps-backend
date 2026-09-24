package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/auth"
	"github.com/stageops/backend/internal/couch"
	"github.com/stageops/backend/internal/equipment"
	"github.com/stageops/backend/internal/events"
	"github.com/stageops/backend/internal/incidents"
	"github.com/stageops/backend/internal/modules"
	"github.com/stageops/backend/internal/projects"
	"github.com/stageops/backend/internal/team"
)

func main() {
	app := fiber.New(fiber.Config{
		ErrorHandler: globalErrorHandler,
	})

	app.Use(securityHeaders())
	app.Use(cors.New(cors.Config{
		AllowOrigins: envOr("CORS_ORIGINS", "http://localhost:8080"),
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PATCH, DELETE, OPTIONS",
	}))

	couchCfg := auth.CouchConfig{
		BaseURL:  mustEnv("COUCHDB_URL"),
		DB:       mustEnv("COUCHDB_DB"),
		Username: mustEnv("COUCHDB_USER"),
		Password: mustEnv("COUCHDB_PASSWORD"),
	}
	sharedCouchCfg := couch.Config{
		BaseURL:  couchCfg.BaseURL,
		DB:       couchCfg.DB,
		Username: couchCfg.Username,
		Password: couchCfg.Password,
	}

	authRepo := auth.NewCouchDBRepository(couchCfg)
	auditRepo := audit.NewCouchDBRepository(audit.CouchConfig{
		BaseURL:  couchCfg.BaseURL,
		DB:       couchCfg.DB,
		Username: couchCfg.Username,
		Password: couchCfg.Password,
	})
	jwtSecret := mustEnv("JWT_SECRET")
	authService := auth.NewService(authRepo, auditRepo, jwtSecret)
	authHandler := auth.NewHandler(authService)

	moduleRepo := modules.NewCouchDBRepository(modules.CouchConfig{
		BaseURL:  couchCfg.BaseURL,
		DB:       couchCfg.DB,
		Username: couchCfg.Username,
		Password: couchCfg.Password,
	})
	moduleService := modules.NewService(moduleRepo, modules.NewCache(), auditRepo)
	moduleHandler := modules.NewHandler(moduleService)
	projectService := projects.NewService(projects.NewCouchDBRepository(sharedCouchCfg), auditRepo)
	projectHandler := projects.NewHandler(projectService)

	equipmentHandler := equipment.NewHandler(equipment.NewService(equipment.NewRepository(sharedCouchCfg), auditRepo))
	eventsHandler := events.NewHandler(events.NewRepository(sharedCouchCfg))
	incidentsHandler := incidents.NewHandler(incidents.NewService(incidents.NewRepository(sharedCouchCfg), auditRepo))
	teamHandler := team.NewHandler(team.NewRepository(sharedCouchCfg))

	rateLimitResponse := func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": fiber.Map{
				"code":    "RATE_LIMIT_EXCEEDED",
				"message": "Trop de requêtes. Réessayez plus tard.",
			},
		})
	}
	loginLimiter := limiter.New(limiter.Config{
		Max:          5,
		Expiration:   time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string { return c.IP() },
		LimitReached: rateLimitResponse,
	})
	registerLimiter := limiter.New(limiter.Config{
		Max:          10,
		Expiration:   time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string { return c.IP() },
		LimitReached: rateLimitResponse,
	})

	api := app.Group("/api")
	api.Get("/health", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
	})
	authGroup := api.Group("/auth")
	authGroup.Post("/register", registerLimiter, authHandler.Register)
	authGroup.Post("/login", loginLimiter, authHandler.Login)
	authGroup.Get("/me", auth.JWTMiddleware(jwtSecret), authHandler.Me)

	usersGroup := api.Group("/users", auth.JWTMiddleware(jwtSecret))
	usersGroup.Patch("/:id/role", auth.RequireRole(auth.RoleRG), authHandler.UpdateUserRole)
	usersGroup.Patch("/:id/modules", auth.RequireRole(auth.RoleRG), authHandler.UpdateUserModules)

	modulesGroup := api.Group("/modules", auth.JWTMiddleware(jwtSecret), auth.RequireRole(auth.RoleRG))
	modulesGroup.Get("/", moduleHandler.GetAll)
	modulesGroup.Patch("/:name/toggle", moduleHandler.Toggle)

	projectsGroup := api.Group("/projects", auth.JWTMiddleware(jwtSecret))
	projectsGroup.Get("/", projectHandler.List)
	projectsGroup.Post("/", auth.RequireRole(auth.RoleRG), projectHandler.Create)
	projectsGroup.Get("/:id", projectHandler.Get)
	projectsGroup.Patch("/:id", auth.RequireRole(auth.RoleRG), projectHandler.Update)
	projectsGroup.Delete("/:id", auth.RequireRole(auth.RoleRG), projectHandler.Delete)

	equipmentGroup := api.Group("/projects/:projectId/equipment/:module", auth.JWTMiddleware(jwtSecret), auth.RequireProjectModule("", projectService))
	equipmentGroup.Get("/", equipmentHandler.List)
	equipmentGroup.Post("/", equipmentHandler.Create)
	equipmentGroup.Get("/:id", equipmentHandler.Get)
	equipmentGroup.Patch("/:id", equipmentHandler.Update)
	equipmentGroup.Delete("/:id", equipmentHandler.Delete)

	eventsGroup := api.Group("/events", auth.JWTMiddleware(jwtSecret))
	eventsGroup.Get("/", eventsHandler.List)
	eventsGroup.Post("/", eventsHandler.Create)
	eventsGroup.Get("/:id", eventsHandler.Get)
	eventsGroup.Patch("/:id", eventsHandler.Update)
	eventsGroup.Delete("/:id", auth.RequireRole(auth.RoleRG), eventsHandler.Delete)

	incidentsGroup := api.Group("/projects/:projectId/incidents/:module", auth.JWTMiddleware(jwtSecret), auth.RequireProjectModule("", projectService))
	incidentsGroup.Get("/", incidentsHandler.List)
	incidentsGroup.Post("/", incidentsHandler.Create)
	incidentsGroup.Get("/:id", incidentsHandler.Get)
	incidentsGroup.Patch("/:id", incidentsHandler.Update)
	incidentsGroup.Delete("/:id", incidentsHandler.Delete)

	teamGroup := api.Group("/team", auth.JWTMiddleware(jwtSecret))
	teamGroup.Get("/", teamHandler.List)
	teamGroup.Post("/", auth.RequireRole(auth.RoleRG), teamHandler.Create)
	teamGroup.Get("/:id", teamHandler.Get)
	teamGroup.Patch("/:id", auth.RequireRole(auth.RoleRG), teamHandler.Update)
	teamGroup.Delete("/:id", auth.RequireRole(auth.RoleRG), teamHandler.Delete)

	port := envOr("APP_PORT", "3000")
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	if tlsCert != "" && tlsKey != "" {
		log.Printf("TLS enabled — listening on :%s", port)
		log.Fatal(app.ListenTLS(":"+port, tlsCert, tlsKey))
	}

	log.Printf("TLS not configured — listening on :%s (HTTP only)", port)
	log.Fatal(app.Listen(":" + port))
}

func securityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		return c.Next()
	}
}

func globalErrorHandler(c *fiber.Ctx, _ error) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    "INTERNAL_ERROR",
			"message": "Une erreur interne est survenue.",
		},
	})
}

func mustEnv(key string) string {
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("required environment variable not set: %s", key)
	}
	return value
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
