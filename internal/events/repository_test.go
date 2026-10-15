package events

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stageops/backend/internal/couch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepositoryRejectsForeignDocumentOnUpdate(t *testing.T) {
	t.Parallel()

	writeCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			writeCalled = true
			w.WriteHeader(http.StatusCreated)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"_id":"user::1","_rev":"1-a","type":"user"}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	repository := NewRepository(couch.Config{BaseURL: server.URL, DB: "stageops"})
	_, err := repository.Update(context.Background(), "user::1", &Input{Title: "Invalid target"})

	assert.ErrorIs(t, err, ErrNotFound)
	assert.False(t, writeCalled)
}

func TestRepositoryRejectsForeignDocumentOnDelete(t *testing.T) {
	t.Parallel()

	deleteCalled := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			deleteCalled = true
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, err := w.Write([]byte(`{"_id":"project::1","_rev":"1-a","type":"project"}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	repository := NewRepository(couch.Config{BaseURL: server.URL, DB: "stageops"})
	err := repository.Delete(context.Background(), "project::1")

	assert.True(t, errors.Is(err, ErrNotFound))
	assert.False(t, deleteCalled)
}
