package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateTokenRejectsOtherHMACAlgorithms(t *testing.T) {
	claims := Claims{
		UserID: "user::abc",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signed, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	_, err = validateToken(signed, "test-secret")
	assert.Error(t, err)
}

func TestAccessTokenContainsRequiredSecurityClaims(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cfg := JWTConfig{Secret: "test-secret", Issuer: "issuer", Audience: "audience", TTL: 15 * time.Minute}
	signed, err := generateAccessToken(
		"user::abc", "user@example.com", RoleSon, "theatre::one",
		[]string{RoleSon}, "session::one", cfg, now,
	)
	require.NoError(t, err)

	claims, err := validateAccessToken(signed, cfg)
	require.NoError(t, err)
	assert.Equal(t, "user::abc", claims.Subject)
	assert.Equal(t, "session::one", claims.ID)
	assert.Equal(t, "theatre::one", claims.TheatreID)
	assert.Equal(t, "access", claims.TokenType)
	assert.True(t, now.Add(15*time.Minute).Equal(claims.ExpiresAt.Time))
}

func TestValidateAccessTokenRejectsWrongAudience(t *testing.T) {
	cfg := JWTConfig{Secret: "test-secret", Issuer: "issuer", Audience: "audience", TTL: time.Minute}
	signed, err := generateAccessToken(
		"user::abc", "user@example.com", RoleSon, "theatre::one", nil, "session::one", cfg, time.Now(),
	)
	require.NoError(t, err)

	wrongAudience := cfg
	wrongAudience.Audience = "another-audience"
	_, err = validateAccessToken(signed, wrongAudience)
	assert.Error(t, err)
}
