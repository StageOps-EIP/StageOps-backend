package auth

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const defaultOfflineTTL = 7 * 24 * time.Hour

// OfflineSignerConfig defines the asymmetric offline-grant contract.
type OfflineSignerConfig struct {
	PrivateKeyBase64 string
	KeyID            string
	Issuer           string
	Audience         string
	TTL              time.Duration
}

// OfflineClaims are verified locally and are never accepted as API access tokens.
type OfflineClaims struct {
	UserID          string   `json:"user_id"`
	Email           string   `json:"email"`
	Role            string   `json:"role"`
	AssignedModules []string `json:"assigned_modules"`
	TheatreID       string   `json:"theatre_id"`
	DeviceID        string   `json:"device_id"`
	TokenType       string   `json:"token_type"`
	jwt.RegisteredClaims
}

// OfflineSigner signs grants and exposes only its public key as JWKS.
type OfflineSigner struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	issuer     string
	audience   string
	ttl        time.Duration
}

// NewOfflineSigner accepts either a 32-byte seed or a 64-byte private key.
func NewOfflineSigner(cfg OfflineSignerConfig) (*OfflineSigner, error) {
	raw, err := base64.StdEncoding.DecodeString(cfg.PrivateKeyBase64)
	if err != nil {
		return nil, fmt.Errorf("decoding offline signing key: %w", err)
	}
	var privateKey ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(append([]byte(nil), raw...))
	default:
		return nil, fmt.Errorf("offline signing key must contain a 32-byte seed or 64-byte private key")
	}
	if cfg.KeyID == "" || cfg.Issuer == "" || cfg.Audience == "" {
		return nil, fmt.Errorf("offline key ID, issuer and audience are required")
	}
	if cfg.TTL <= 0 || cfg.TTL > defaultOfflineTTL {
		cfg.TTL = defaultOfflineTTL
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return &OfflineSigner{
		privateKey: privateKey, publicKey: publicKey, keyID: cfg.KeyID,
		issuer: cfg.Issuer, audience: cfg.Audience, ttl: cfg.TTL,
	}, nil
}

func (s *OfflineSigner) Sign(user *User, deviceID string, now time.Time) (string, time.Time, error) {
	expiresAt := now.Add(s.ttl)
	claims := OfflineClaims{
		UserID: user.ID, Email: user.Email, Role: user.Role,
		AssignedModules: append([]string(nil), user.AssignedModules...),
		TheatreID:       user.TheatreID, DeviceID: deviceID, TokenType: "offline",
		RegisteredClaims: jwt.RegisteredClaims{
			Audience: jwt.ClaimStrings{s.audience}, ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID: deviceID, IssuedAt: jwt.NewNumericDate(now), Issuer: s.issuer,
			NotBefore: jwt.NewNumericDate(now), Subject: user.ID,
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = s.keyID
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("signing offline grant: %w", err)
	}
	return signed, expiresAt, nil
}

// JWKS returns the public Ed25519 key used by clients to verify offline grants.
func (s *OfflineSigner) JWKS() map[string]interface{} {
	return map[string]interface{}{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": s.keyID, "x": base64.RawURLEncoding.EncodeToString(s.publicKey),
		}},
	}
}
