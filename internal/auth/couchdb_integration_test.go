//go:build integration

package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCouchDBConcurrentRegistrationAndSessionPersistence(t *testing.T) {
	baseURL := integrationEnv(t, "COUCHDB_TEST_URL")
	username := integrationEnv(t, "COUCHDB_TEST_USER")
	password := integrationEnv(t, "COUCHDB_TEST_PASSWORD")
	database := fmt.Sprintf("stageops_auth_test_%d", time.Now().UnixNano())
	client := &http.Client{Timeout: 10 * time.Second}
	request := func(method, path string, body []byte) *http.Response {
		t.Helper()
		req, err := http.NewRequest(method, baseURL+"/"+url.PathEscape(database)+path, bytes.NewReader(body))
		require.NoError(t, err)
		req.SetBasicAuth(username, password)
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := client.Do(req)
		require.NoError(t, err)
		return resp
	}

	createResponse := request(http.MethodPut, "", nil)
	require.Equal(t, http.StatusCreated, createResponse.StatusCode)
	createResponse.Body.Close()
	t.Cleanup(func() {
		deleteResponse := request(http.MethodDelete, "", nil)
		deleteResponse.Body.Close()
	})

	design := map[string]interface{}{
		"_id": "_design/users",
		"views": map[string]interface{}{
			"by_email": map[string]string{
				"map": `function(doc) { if (doc.type === "user" && doc.email) emit(doc.email, null); }`,
			},
			"by_role": map[string]string{
				"map": `function(doc) { if (doc.type === "user" && doc.role) emit(doc.role, null); }`,
			},
			"by_theatre": map[string]string{
				"map": `function(doc) { if (doc.type === "user" && doc.theatre_id) emit([doc.theatre_id, doc.email], null); }`,
			},
		},
	}
	designBody, err := json.Marshal(design)
	require.NoError(t, err)
	designResponse := request(http.MethodPut, "/_design/users", designBody)
	require.Equal(t, http.StatusCreated, designResponse.StatusCode)
	designResponse.Body.Close()

	cfg := CouchConfig{BaseURL: baseURL, DB: database, Username: username, Password: password}
	userRepo := NewCouchDBRepository(cfg)
	sessionRepo := NewCouchDBSessionRepository(cfg)
	service := NewServiceWithConfig(userRepo, nil, ServiceConfig{
		JWT: JWTConfig{
			Secret: "integration-jwt-secret-at-least-32-characters", Issuer: "integration",
			Audience: "integration-clients", TTL: 15 * time.Minute,
		},
		UserIDSecret:          "integration-user-id-secret-at-least-32-characters",
		RegistrationTheatreID: "theatre::integration",
		SessionRepository:     sessionRepo,
		RefreshTTL:            time.Hour,
	})

	start := make(chan struct{})
	type registrationResult struct {
		tokens *TokenPair
		err    error
	}
	results := make(chan registrationResult, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			tokens, registerErr := service.Register(context.Background(), "unique@example.com", "SecurePass1!")
			results <- registrationResult{tokens: tokens, err: registerErr}
		}()
	}
	close(start)
	waitGroup.Wait()
	close(results)

	var successes, conflicts int
	var registeredTokens *TokenPair
	for result := range results {
		switch {
		case result.err == nil:
			successes++
			registeredTokens = result.tokens
		case errors.Is(result.err, ErrEmailAlreadyExists):
			conflicts++
		default:
			t.Fatalf("unexpected registration error: %v", result.err)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, conflicts)
	require.NotNil(t, registeredTokens)
	require.NotEmpty(t, registeredTokens.RefreshToken)

	user, err := userRepo.FindByEmail(context.Background(), "unique@example.com")
	require.NoError(t, err)
	assert.Equal(t, "theatre::integration", user.TheatreID)

	theatreUsers, err := userRepo.ListByTheatre(context.Background(), "theatre::integration", 10, 0)
	require.NoError(t, err)
	require.Len(t, theatreUsers, 1)
	assert.Equal(t, user.ID, theatreUsers[0].ID)
	assert.NotEqual(t, "SecurePass1!", user.PasswordHash)
	assert.True(t, comparePassword(user.PasswordHash, "SecurePass1!"))

	sessionID, err := parseSessionRefreshToken(registeredTokens.RefreshToken)
	require.NoError(t, err)
	storedSession, err := sessionRepo.FindByID(context.Background(), sessionID)
	require.NoError(t, err)
	assert.Equal(t, hashRefreshToken(registeredTokens.RefreshToken), storedSession.RefreshTokenHash)
	assert.Equal(t, user.ID, storedSession.UserID)

	refreshStart := make(chan struct{})
	refreshResults := make(chan registrationResult, 2)
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-refreshStart
			tokens, refreshErr := service.Refresh(context.Background(), registeredTokens.RefreshToken)
			refreshResults <- registrationResult{tokens: tokens, err: refreshErr}
		}()
	}
	close(refreshStart)
	waitGroup.Wait()
	close(refreshResults)

	var rotatedTokens *TokenPair
	successes, conflicts = 0, 0
	for result := range refreshResults {
		switch {
		case result.err == nil:
			successes++
			rotatedTokens = result.tokens
		case errors.Is(result.err, ErrInvalidRefresh):
			conflicts++
		default:
			t.Fatalf("unexpected refresh error: %v", result.err)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, conflicts)
	require.NotNil(t, rotatedTokens)

	_, err = service.Refresh(context.Background(), rotatedTokens.RefreshToken)
	assert.ErrorIs(t, err, ErrInvalidRefresh, "a concurrent replay must revoke the complete token family")

	loginTokens, err := service.Login(context.Background(), "unique@example.com", "SecurePass1!")
	require.NoError(t, err)
	require.NoError(t, service.Logout(context.Background(), loginTokens.RefreshToken))

	_, err = service.Refresh(context.Background(), loginTokens.RefreshToken)
	assert.ErrorIs(t, err, ErrInvalidRefresh)
}

func integrationEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s is required for integration tests", key)
	}
	return value
}
