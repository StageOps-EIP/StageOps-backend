package projects

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stageops/backend/internal/couch"
	"github.com/stageops/backend/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepositoryListUsesAuthenticatedTheatreViewKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops/_design/projects/_view/by_theatre", r.URL.Path)
		assert.Equal(t, `"theatre::one"`, r.URL.Query().Get("key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[]}`)
	}))
	t.Cleanup(server.Close)
	repo := NewCouchDBRepository(couch.Config{BaseURL: server.URL, DB: "stageops"})
	ctx := tenant.WithTheatreID(context.Background(), "theatre::one")

	projects, err := repo.List(ctx)

	require.NoError(t, err)
	assert.Empty(t, projects)
}

func TestRepositoryFindByIDHidesAnotherTheatre(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"_id":"project::one","type":"project","theatre_id":"theatre::other"}`)
	}))
	t.Cleanup(server.Close)
	repo := NewCouchDBRepository(couch.Config{BaseURL: server.URL, DB: "stageops"})
	ctx := tenant.WithTheatreID(context.Background(), "theatre::one")

	_, err := repo.FindByID(ctx, "project::one")

	assert.ErrorIs(t, err, ErrNotFound)
}
