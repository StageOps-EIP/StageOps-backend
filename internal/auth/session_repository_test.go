package auth

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCouchDBSessionRepositoryFindByRefreshHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops_auth/_design/sessions/_view/by_refresh_hash", r.URL.Path)
		assert.Equal(t, `"hash-value"`, r.URL.Query().Get("key"))
		assert.Equal(t, "true", r.URL.Query().Get("include_docs"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[{"doc":{"_id":"session::one","_rev":"1-a","type":"session","user_id":"user::one","refresh_token_hash":"hash-value"}}]}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBSessionRepository(CouchConfig{BaseURL: server.URL, DB: "stageops_auth"})
	session, err := repo.FindByRefreshHash(context.Background(), "hash-value")

	require.NoError(t, err)
	assert.Equal(t, "session::one", session.ID)
	assert.Equal(t, "user::one", session.UserID)
}

func TestCouchDBSessionRepositoryFindByIDRejectsForeignDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"_id":"user::one","type":"user"}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBSessionRepository(CouchConfig{BaseURL: server.URL, DB: "stageops_auth"})
	_, err := repo.FindByID(context.Background(), "user::one")

	require.ErrorIs(t, err, ErrSessionNotFound)
}
