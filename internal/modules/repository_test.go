package modules

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stageops/backend/internal/tenant"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepositoryGetByNameUsesTheatreScopedDocumentID(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops/module::theatre::one::son", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"_id":"module::theatre::one::son","type":"module","theatre_id":"theatre::one","name":"son","active":true}`)
	}))
	t.Cleanup(server.Close)
	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL, DB: "stageops"})
	ctx := tenant.WithTheatreID(context.Background(), "theatre::one")

	module, err := repo.GetByName(ctx, "son")

	require.NoError(t, err)
	assert.True(t, module.Active)
}

func TestRepositoryGetByNameRejectsAnotherTheatreDocument(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"_id":"module::other::son","type":"module","theatre_id":"other","name":"son","active":true}`)
	}))
	t.Cleanup(server.Close)
	repo := NewCouchDBRepository(CouchConfig{BaseURL: server.URL, DB: "stageops"})
	ctx := tenant.WithTheatreID(context.Background(), "theatre::one")

	_, err := repo.GetByName(ctx, "son")

	assert.ErrorIs(t, err, ErrModuleNotFound)
}
