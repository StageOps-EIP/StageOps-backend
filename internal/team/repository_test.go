package team

import (
	"context"
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
		_, err := w.Write([]byte(`{"_id":"audit::1","_rev":"1-a","type":"audit"}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	repository := NewRepository(couch.Config{BaseURL: server.URL, DB: "stageops"})
	_, err := repository.Update(context.Background(), "audit::1", &Input{
		Name:  "Invalid target",
		Email: "invalid@example.com",
	})

	assert.ErrorIs(t, err, ErrNotFound)
	assert.False(t, writeCalled)
}
