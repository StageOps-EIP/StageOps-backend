package auth

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestOfflineSigner(t *testing.T) *OfflineSigner {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	_, err := rand.Read(seed)
	require.NoError(t, err)
	signer, err := NewOfflineSigner(OfflineSignerConfig{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString(seed), KeyID: "offline-2026-01",
		Issuer: "stageops-api", Audience: "stageops-offline", TTL: 24 * time.Hour,
	})
	require.NoError(t, err)
	return signer
}

func TestOfflineSignerCreatesPubliclyVerifiableGrant(t *testing.T) {
	signer := newTestOfflineSigner(t)
	now := time.Now().UTC().Truncate(time.Second)
	user := &User{
		ID: "user::one", Email: "user@example.com", Role: RoleSon,
		TheatreID: "theatre::one", AssignedModules: []string{RoleSon},
	}
	signed, expiresAt, err := signer.Sign(user, "device::one", now)
	require.NoError(t, err)

	token, err := jwt.ParseWithClaims(signed, &OfflineClaims{}, func(token *jwt.Token) (interface{}, error) {
		assert.Equal(t, jwt.SigningMethodEdDSA, token.Method)
		assert.Equal(t, "offline-2026-01", token.Header["kid"])
		return signer.publicKey, nil
	}, jwt.WithAudience("stageops-offline"), jwt.WithIssuer("stageops-api"))
	require.NoError(t, err)
	claims := token.Claims.(*OfflineClaims)
	assert.Equal(t, "offline", claims.TokenType)
	assert.Equal(t, user.TheatreID, claims.TheatreID)
	assert.Equal(t, "device::one", claims.DeviceID)
	assert.True(t, now.Add(24*time.Hour).Equal(expiresAt))
}

func TestOfflineSignerJWKSContainsOnlyPublicKey(t *testing.T) {
	signer := newTestOfflineSigner(t)
	keys := signer.JWKS()["keys"].([]map[string]string)

	require.Len(t, keys, 1)
	assert.Equal(t, "OKP", keys[0]["kty"])
	assert.Equal(t, "Ed25519", keys[0]["crv"])
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(signer.publicKey), keys[0]["x"])
}

func TestNewOfflineSignerRejectsInvalidKey(t *testing.T) {
	_, err := NewOfflineSigner(OfflineSignerConfig{
		PrivateKeyBase64: base64.StdEncoding.EncodeToString([]byte("too-short")),
		KeyID:            "key", Issuer: "issuer", Audience: "audience",
	})

	require.Error(t, err)
}
