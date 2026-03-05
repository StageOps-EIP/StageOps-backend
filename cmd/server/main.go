package main

import (
	"log"
	"os"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/stageops/backend/internal/audit"
	"github.com/stageops/backend/internal/auth"
)

func main() {
	app := fiber.New(fiber.Config{
		ErrorHandler: globalErrorHandler,
	})

	app.Use(securityHeaders())

	couchCfg := auth.CouchConfig{
		BaseURL:  mustEnv("COUCHDB_URL"),
		DB:       mustEnv("COUCHDB_DB"),
		Username: mustEnv("COUCHDB_USER"),
		Password: mustEnv("COUCHDB_PASSWORD"),
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

	port := envOr("APP_PORT", "3000")
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

// securityHeaders sets mandatory security response headers on every request.
func securityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "DENY")
		c.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		return c.Next()
	}
}

// globalErrorHandler is the Fiber error handler of last resort.
func globalErrorHandler(c *fiber.Ctx, _ error) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error": fiber.Map{
			"code":    "INTERNAL_ERROR",
			"message": "Une erreur interne est survenue.",
		},
	})
}

// mustEnv reads an environment variable or terminates the process.
func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable not set: %s", key)
	}
	return v
}

// envOr reads an environment variable with a fallback default.
func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
