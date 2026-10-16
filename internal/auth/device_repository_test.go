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

func TestCouchDBDeviceRepositoryListsOnlyDeviceDocuments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops_auth/_design/devices/_view/by_user", r.URL.Path)
		assert.Equal(t, `"user::one"`, r.URL.Query().Get("key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[{"doc":{"_id":"device::one","type":"device","user_id":"user::one","name":"Console"}},{"doc":{"_id":"other::one","type":"other"}}]}`)
	}))
	t.Cleanup(server.Close)

	repo := NewCouchDBDeviceRepository(CouchConfig{BaseURL: server.URL, DB: "stageops_auth"})
	devices, err := repo.ListByUser(context.Background(), "user::one")

	require.NoError(t, err)
	require.Len(t, devices, 1)
	assert.Equal(t, "device::one", devices[0].ID)
}
