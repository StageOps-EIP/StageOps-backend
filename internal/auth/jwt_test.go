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
