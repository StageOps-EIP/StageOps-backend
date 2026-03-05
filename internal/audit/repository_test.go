package audit

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCouchDBRepository_Log_WritesCorrectDocument(t *testing.T) {
	var received AuditEntry
	var method, path, contentType, authHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
		path = r.URL.Path
		contentType = r.Header.Get("Content-Type")
		authHeader = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	repo := NewCouchDBRepository(CouchConfig{
		BaseURL:  srv.URL,
		DB:       "stageops",
		Username: "admin",
		Password: "secret",
	})

	entry := AuditEntry{
		ID:         "audit::test-uuid",
		Type:       "audit",
		Action:     ActionRoleChanged,
		AuthorID:   "user::author",
		AuthorRole: "rg",
		TargetID:   "user::target",
		CreatedAt:  time.Now().UTC().Truncate(time.Second),
	}

	err := repo.Log(context.Background(), entry)

	assert.NoError(t, err)
	assert.Equal(t, http.MethodPut, method)
	assert.Equal(t, "/stageops/audit::test-uuid", path)
	assert.Equal(t, "application/json", contentType)
	assert.True(t, strings.HasPrefix(authHeader, "Basic "), "expected Basic auth header")
	assert.Equal(t, entry.ID, received.ID)
	assert.Equal(t, entry.Action, received.Action)
	assert.Equal(t, entry.AuthorID, received.AuthorID)
	assert.Equal(t, entry.AuthorRole, received.AuthorRole)
	assert.Equal(t, entry.TargetID, received.TargetID)
}

func TestCouchDBRepository_Log_CouchDBConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
	}))
	defer srv.Close()

	repo := NewCouchDBRepository(CouchConfig{
		BaseURL:  srv.URL,
		DB:       "stageops",
		Username: "admin",
		Password: "secret",
	})

	err := repo.Log(context.Background(), AuditEntry{
		ID:     "audit::dup",
		Type:   "audit",
		Action: ActionRoleChanged,
	})

	assert.Error(t, err)
}

func TestCouchDBRepository_Log_CouchDBInternalError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	repo := NewCouchDBRepository(CouchConfig{
		BaseURL:  srv.URL,
		DB:       "stageops",
		Username: "admin",
		Password: "secret",
	})

	err := repo.Log(context.Background(), AuditEntry{
		ID:     "audit::err",
		Type:   "audit",
		Action: ActionIncidentReported,
	})

	assert.Error(t, err)
}

func TestCouchDBRepository_Log_NetworkFailure(t *testing.T) {
	// Point at a port that refuses connections.
	repo := NewCouchDBRepository(CouchConfig{
		BaseURL:  "http://127.0.0.1:1",
		DB:       "stageops",
		Username: "admin",
		Password: "secret",
	})

	err := repo.Log(context.Background(), AuditEntry{
		ID:     "audit::net-err",
		Type:   "audit",
		Action: ActionMaterialUpdated,
	})

	assert.Error(t, err)
}
