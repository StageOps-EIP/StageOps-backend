package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCouchDBRepositoryFindByIDRejectsForeignDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops/project::one", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"_id":"project::one","type":"project"}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL + "/", DB: "stageops"})
	user, err := repo.FindByID(context.Background(), "project::one")

	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserNotFound))
	assert.Nil(t, user)
}

func TestCouchDBRepositoryFindByRole(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops/_design/users/_view/by_role", r.URL.Path)
		assert.Equal(t, `"rg"`, r.URL.Query().Get("key"))
		assert.Equal(t, "1", r.URL.Query().Get("limit"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[{"doc":{"_id":"user::admin","type":"user","email":"admin@example.com","role":"rg"}}]}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL, DB: "stageops"})
	user, err := repo.FindByRole(context.Background(), RoleRG)

	require.NoError(t, err)
	assert.Equal(t, "user::admin", user.ID)
	assert.Equal(t, RoleRG, user.Role)
}
