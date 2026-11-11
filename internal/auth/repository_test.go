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

func TestCouchDBRepositoryListByTheatre(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops_auth/_design/users/_view/by_theatre", r.URL.Path)
		assert.Equal(t, `["theatre::one"]`, r.URL.Query().Get("startkey"))
		assert.Equal(t, `["theatre::one",{}]`, r.URL.Query().Get("endkey"))
		assert.Equal(t, "true", r.URL.Query().Get("include_docs"))
		assert.Equal(t, "25", r.URL.Query().Get("limit"))
		assert.Equal(t, "50", r.URL.Query().Get("skip"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[
			{"doc":{"_id":"user::a","type":"user","email":"a@example.com","theatre_id":"theatre::one"}},
			{"doc":{"_id":"user::b","type":"user","email":"b@example.com","theatre_id":"theatre::other"}},
			{"doc":{"_id":"session::x","type":"session","theatre_id":"theatre::one"}}
		]}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL, DB: "stageops_auth"})
	users, err := repo.ListByTheatre(context.Background(), "theatre::one", 25, 50)

	require.NoError(t, err)
	require.Len(t, users, 1, "documents of another type or theatre are dropped")
	assert.Equal(t, "user::a", users[0].ID)
}

func TestCouchDBRepositoryFindByVerificationHash(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops_auth/_design/users/_view/by_verification_hash", r.URL.Path)
		assert.Equal(t, `"verification-hash"`, r.URL.Query().Get("key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[{"doc":{"_id":"user::one","type":"user","email":"user@example.com","verification_token_hash":"verification-hash"}}]}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL, DB: "stageops_auth"})
	user, err := repo.FindByVerificationHash(context.Background(), "verification-hash")

	require.NoError(t, err)
	assert.Equal(t, "user::one", user.ID)
}

func TestCouchDBRepositoryUpdateUserReturnsTypedConflict(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/stageops_auth/user::one", r.URL.Path)
		w.WriteHeader(http.StatusConflict)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL, DB: "stageops_auth"})
	err := repo.UpdateUser(context.Background(), &User{ID: "user::one", Rev: "1-old", Type: "user"})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUserConflict)
}
