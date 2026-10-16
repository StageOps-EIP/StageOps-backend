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
		},
	}
	designBody, err := json.Marshal(design)
	require.NoError(t, err)
	designResponse := request(http.MethodPut, "/_design/users", designBody)
	require.Equal(t, http.StatusCreated, designResponse.StatusCode)
	designResponse.Body.Close()

	cfg := CouchConfig{BaseURL: baseURL, DB: database, Username: username, Password: password}
	userRepo := NewCouchDBRepository(cfg)
	service := NewServiceWithConfig(userRepo, nil, ServiceConfig{
		JWT: JWTConfig{
			Secret: "integration-jwt-secret-at-least-32-characters", Issuer: "integration",
			Audience: "integration-clients", TTL: 15 * time.Minute,
		},
		UserIDSecret:          "integration-user-id-secret-at-least-32-characters",
		RegistrationTheatreID: "theatre::integration",
	})

	start := make(chan struct{})
	errorsByAttempt := make(chan error, 2)
	var waitGroup sync.WaitGroup
	for range 2 {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			<-start
			_, registerErr := service.Register(context.Background(), "unique@example.com", "SecurePass1!")
			errorsByAttempt <- registerErr
		}()
	}
	close(start)
	waitGroup.Wait()
	close(errorsByAttempt)

	var successes, conflicts int
	for registerErr := range errorsByAttempt {
		switch {
		case registerErr == nil:
			successes++
		case errors.Is(registerErr, ErrEmailAlreadyExists):
			conflicts++
		default:
			t.Fatalf("unexpected registration error: %v", registerErr)
		}
	}
	assert.Equal(t, 1, successes)
	assert.Equal(t, 1, conflicts)

	user, err := userRepo.FindByEmail(context.Background(), "unique@example.com")
	require.NoError(t, err)
	assert.Equal(t, "theatre::integration", user.TheatreID)
	assert.NotEqual(t, "SecurePass1!", user.PasswordHash)
	assert.True(t, comparePassword(user.PasswordHash, "SecurePass1!"))

	sessionRepo := NewCouchDBSessionRepository(cfg)
	now := time.Now().UTC().Truncate(time.Second)
	session := &Session{
		ID: "session::integration", Type: "session", UserID: user.ID,
		TheatreID: user.TheatreID, RefreshTokenHash: "integration-hash",
		CreatedAt: now, LastUsedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	require.NoError(t, sessionRepo.Create(context.Background(), session))
	storedSession, err := sessionRepo.FindByID(context.Background(), session.ID)
	require.NoError(t, err)
	assert.Equal(t, session.RefreshTokenHash, storedSession.RefreshTokenHash)
}

func integrationEnv(t *testing.T, key string) string {
	t.Helper()
	value := os.Getenv(key)
	if value == "" {
		t.Fatalf("%s is required for integration tests", key)
	}
	return value
}
