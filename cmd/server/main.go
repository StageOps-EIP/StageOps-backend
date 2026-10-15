package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/gofiber/fiber/v2/middleware/requestid"
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
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	app := fiber.New(fiber.Config{
		BodyLimit:             2 * 1024 * 1024,
		DisableStartupMessage: true,
		ErrorHandler:          globalErrorHandler,
		IdleTimeout:           60 * time.Second,
		ProxyHeader:           "X-Forwarded-For",
		ReadTimeout:           15 * time.Second,
		WriteTimeout:          30 * time.Second,
	})

	app.Use(recover.New())
	app.Use(requestid.New())
	app.Use(logger.New(logger.Config{
		Format:   "${time} ${status} ${latency} ${ip} ${method} ${path} request_id=${locals:requestid}\n",
		TimeZone: "UTC",
	}))
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
	jwtSecret := mustSecret("JWT_SECRET", 32)
	authService := auth.NewService(authRepo, auditRepo, jwtSecret)
	if err := bootstrapAdminFromEnv(authService); err != nil {
		return err
	}
	authHandler := auth.NewHandler(authService)
	authenticate := auth.JWTMiddleware(jwtSecret, authRepo)

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

	healthClient := couch.New(sharedCouchCfg)
	ready := readinessHandler(healthClient)

	api := app.Group("/api")
	api.Get("/health/live", func(c *fiber.Ctx) error {
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
	})
	api.Get("/health/ready", ready)
	api.Get("/health", ready)
	authGroup := api.Group("/auth")
	if envBool("ALLOW_PUBLIC_REGISTRATION", true) {
		authGroup.Post("/register", registerLimiter, authHandler.Register)
	}
	authGroup.Post("/login", loginLimiter, authHandler.Login)
	authGroup.Get("/me", authenticate, authHandler.Me)

	usersGroup := api.Group("/users", authenticate)
	usersGroup.Patch("/:id/role", auth.RequireRole(auth.RoleRG), authHandler.UpdateUserRole)
	usersGroup.Patch("/:id/modules", auth.RequireRole(auth.RoleRG), authHandler.UpdateUserModules)

	modulesGroup := api.Group("/modules", authenticate, auth.RequireRole(auth.RoleRG))
	modulesGroup.Get("/", moduleHandler.GetAll)
	modulesGroup.Patch("/:name/toggle", moduleHandler.Toggle)

	projectsGroup := api.Group("/projects", authenticate)
	projectsGroup.Get("/", projectHandler.List)
	projectsGroup.Post("/", auth.RequireRole(auth.RoleRG), projectHandler.Create)
	projectsGroup.Get("/:id", projectHandler.Get)
	projectsGroup.Patch("/:id", auth.RequireRole(auth.RoleRG), projectHandler.Update)
	projectsGroup.Delete("/:id", auth.RequireRole(auth.RoleRG), projectHandler.Delete)

	equipmentGroup := api.Group("/projects/:projectId/equipment/:module", authenticate, auth.RequireProjectModule("", projectService))
	equipmentGroup.Get("/", equipmentHandler.List)
	equipmentGroup.Post("/", equipmentHandler.Create)
	equipmentGroup.Get("/:id", equipmentHandler.Get)
	equipmentGroup.Patch("/:id", equipmentHandler.Update)
	equipmentGroup.Delete("/:id", equipmentHandler.Delete)

	eventsGroup := api.Group("/events", authenticate)
	eventsGroup.Get("/", eventsHandler.List)
	eventsGroup.Post("/", eventsHandler.Create)
	eventsGroup.Get("/:id", eventsHandler.Get)
	eventsGroup.Patch("/:id", eventsHandler.Update)
	eventsGroup.Delete("/:id", auth.RequireRole(auth.RoleRG), eventsHandler.Delete)

	incidentsGroup := api.Group("/projects/:projectId/incidents/:module", authenticate, auth.RequireProjectModule("", projectService))
	incidentsGroup.Get("/", incidentsHandler.List)
	incidentsGroup.Post("/", incidentsHandler.Create)
	incidentsGroup.Get("/:id", incidentsHandler.Get)
	incidentsGroup.Patch("/:id", incidentsHandler.Update)
	incidentsGroup.Delete("/:id", incidentsHandler.Delete)

	teamGroup := api.Group("/team", authenticate)
	teamGroup.Get("/", teamHandler.List)
	teamGroup.Post("/", auth.RequireRole(auth.RoleRG), teamHandler.Create)
	teamGroup.Get("/:id", teamHandler.Get)
	teamGroup.Patch("/:id", auth.RequireRole(auth.RoleRG), teamHandler.Update)
	teamGroup.Delete("/:id", auth.RequireRole(auth.RoleRG), teamHandler.Delete)

	port := envOr("APP_PORT", "3000")
	tlsCert := os.Getenv("TLS_CERT")
	tlsKey := os.Getenv("TLS_KEY")
	if (tlsCert == "") != (tlsKey == "") {
		return fmt.Errorf("TLS_CERT and TLS_KEY must be configured together")
	}

	serverErrors := make(chan error, 1)
	go func() {
		if tlsCert != "" {
			log.Printf("TLS enabled; listening on :%s", port)
			serverErrors <- app.ListenTLS(":"+port, tlsCert, tlsKey)
			return
		}
		log.Printf("listening on :%s; TLS is expected at the reverse proxy", port)
		serverErrors <- app.Listen(":" + port)
	}()

	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignals)

	select {
	case err := <-serverErrors:
		if err == nil {
			return nil
		}
		return fmt.Errorf("HTTP server stopped: %w", err)
	case received := <-shutdownSignals:
		log.Printf("received %s; shutting down", received)
		if err := app.Shutdown(); err != nil {
			return fmt.Errorf("shutting down HTTP server: %w", err)
		}
		return nil
	}
}

func readinessHandler(client *couch.Client) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), 3*time.Second)
		defer cancel()
		if err := client.Ping(ctx); err != nil {
			return c.Status(fiber.StatusServiceUnavailable).JSON(fiber.Map{
				"status": "unavailable",
			})
		}
		return c.Status(fiber.StatusOK).JSON(fiber.Map{"status": "ok"})
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
	value := os.Getenv(key)
	if value == "" {
		log.Fatalf("required environment variable not set: %s", key)
	}
	return value
}

func mustSecret(key string, minLength int) string {
	value := mustEnv(key)
	if len(value) < minLength {
		log.Fatalf("%s must contain at least %d characters", key, minLength)
	}
	return value
}

func bootstrapAdminFromEnv(service *auth.Service) error {
	email := os.Getenv("BOOTSTRAP_ADMIN_EMAIL")
	password := os.Getenv("BOOTSTRAP_ADMIN_PASSWORD")
	if email == "" && password == "" {
		return nil
	}
	if email == "" || password == "" {
		return fmt.Errorf("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD must be configured together")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := service.BootstrapAdmin(ctx, email, password); err != nil {
		return fmt.Errorf("bootstrapping administrator: %w", err)
	}
	log.Printf("administrator bootstrap check completed")
	return nil
}

func envBool(key string, fallback bool) bool {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		log.Fatalf("%s must be a boolean", key)
	}
	return value
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
