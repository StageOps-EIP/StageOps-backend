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

	repo := auth.NewCouchDBRepository(couchCfg)

	auditRepo := audit.NewCouchDBRepository(audit.CouchConfig{
		BaseURL:  couchCfg.BaseURL,
		DB:       couchCfg.DB,
		Username: couchCfg.Username,
		Password: couchCfg.Password,
	})

	jwtSecret := mustEnv("JWT_SECRET")
	service := auth.NewService(repo, auditRepo, jwtSecret)
	handler := auth.NewHandler(service)

	equipmentHandler := equipment.NewHandler(equipment.NewRepository(sharedCouchCfg))
	eventsHandler := events.NewHandler(events.NewRepository(sharedCouchCfg))
	incidentsHandler := incidents.NewHandler(incidents.NewRepository(sharedCouchCfg))
	teamHandler := team.NewHandler(team.NewRepository(sharedCouchCfg))

	rateLimitResponse := func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
			"error": fiber.Map{
				"code":    "RATE_LIMIT_EXCEEDED",
				"message": "Trop de requêtes. Réessayez plus tard.",
			},
		})
	}

	// Login is capped at 5 req/min per IP to slow down brute-force attempts.
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

	authGroup := api.Group("/auth")
	authGroup.Post("/register", registerLimiter, handler.Register)
	authGroup.Post("/login", loginLimiter, handler.Login)
	authGroup.Get("/me", auth.JWTMiddleware(jwtSecret), handler.Me)

	// User management — RG only.
	usersGroup := api.Group("/users", auth.JWTMiddleware(jwtSecret))
	usersGroup.Patch("/:id/role", auth.RequireRole(auth.RoleRG), handler.UpdateUserRole)

	equip := api.Group("/equipment", auth.JWTMiddleware(jwtSecret))
	equip.Get("/", equipmentHandler.List)
	equip.Post("/", equipmentHandler.Create)
	equip.Get("/:id", equipmentHandler.Get)
	equip.Patch("/:id", equipmentHandler.Update)
	equip.Delete("/:id", auth.RequireRole(auth.RoleRG), equipmentHandler.Delete)

	evts := api.Group("/events", auth.JWTMiddleware(jwtSecret))
	evts.Get("/", eventsHandler.List)
	evts.Post("/", eventsHandler.Create)
	evts.Get("/:id", eventsHandler.Get)
	evts.Patch("/:id", eventsHandler.Update)
	evts.Delete("/:id", auth.RequireRole(auth.RoleRG), eventsHandler.Delete)

	inc := api.Group("/incidents", auth.JWTMiddleware(jwtSecret))
	inc.Get("/", incidentsHandler.List)
	inc.Post("/", incidentsHandler.Create)
	inc.Get("/:id", incidentsHandler.Get)
	inc.Patch("/:id", incidentsHandler.Update)
	inc.Delete("/:id", auth.RequireRole(auth.RoleRG), incidentsHandler.Delete)

	tm := api.Group("/team", auth.JWTMiddleware(jwtSecret))
	tm.Get("/", teamHandler.List)
	tm.Post("/", auth.RequireRole(auth.RoleRG), teamHandler.Create)
	tm.Get("/:id", teamHandler.Get)
	tm.Patch("/:id", auth.RequireRole(auth.RoleRG), teamHandler.Update)
	tm.Delete("/:id", auth.RequireRole(auth.RoleRG), teamHandler.Delete)

	port := envOr("APP_PORT", "3001")
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")

	if tlsCert != "" && tlsKey != "" {
		log.Printf("TLS enabled — listening on :%s", port)
		log.Fatal(app.ListenTLS(":"+port, tlsCert, tlsKey))
	} else {
		log.Printf("TLS not configured — listening on :%s (HTTP only)", port)
		log.Fatal(app.Listen(":" + port))
	}
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
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable not set: %s", key)
	}
	return v
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
