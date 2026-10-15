package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	defaultJWTIssuer   = "stageops-api"
	defaultJWTAudience = "stageops-clients"
	defaultAccessTTL   = 15 * time.Minute
)

// JWTConfig defines the trusted access-token contract.
type JWTConfig struct {
	Secret   string
	Issuer   string
	Audience string
	TTL      time.Duration
}

func defaultJWTConfig(secret string) JWTConfig {
	return JWTConfig{Secret: secret, Issuer: defaultJWTIssuer, Audience: defaultJWTAudience, TTL: defaultAccessTTL}
}

// Claims are the JWT payload fields.
type Claims struct {
	UserID          string   `json:"user_id"`
	Email           string   `json:"email"`
	Role            string   `json:"role"`
	AssignedModules []string `json:"assigned_modules"`
	TheatreID       string   `json:"theatre_id"`
	TokenType       string   `json:"token_type"`
	jwt.RegisteredClaims
}

// generateToken creates a signed HS256 JWT valid for 24 hours.
func generateToken(userID, email, role, secret string) (string, error) {
	return generateTokenWithModules(userID, email, role, nil, secret)
}

// generateTokenWithModules includes the user's current module permissions.
func generateTokenWithModules(userID, email, role string, assignedModules []string, secret string) (string, error) {
	return generateAccessToken(userID, email, role, "theatre-default", assignedModules, uuid.NewString(), defaultJWTConfig(secret), time.Now())
}

func generateAccessToken(userID, email, role, theatreID string, assignedModules []string, sessionID string, cfg JWTConfig, now time.Time) (string, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = defaultAccessTTL
	}
	claims := Claims{
		UserID:          userID,
		Email:           email,
		Role:            role,
		AssignedModules: assignedModules,
		TheatreID:       theatreID,
		TokenType:       "access",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{cfg.Audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(cfg.TTL)),
			ID:        sessionID,
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    cfg.Issuer,
			NotBefore: jwt.NewNumericDate(now),
			Subject:   userID,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	signed, err := token.SignedString([]byte(cfg.Secret))
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}

	return signed, nil
}

// validateToken parses and validates a JWT string, returning its claims.
func validateToken(tokenStr, secret string) (*Claims, error) {
	return validateAccessToken(tokenStr, defaultJWTConfig(secret))
}

func validateAccessToken(tokenStr string, cfg JWTConfig) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if t.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(cfg.Secret), nil
	},
		jwt.WithAudience(cfg.Audience),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(cfg.Issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return nil, fmt.Errorf("parsing token: %w", err)
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid || claims.TokenType != "access" || claims.Subject == "" || claims.ID == "" || claims.UserID != claims.Subject {
		return nil, fmt.Errorf("invalid token claims")
	}

	return claims, nil
}
