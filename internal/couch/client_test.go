package couch

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListByViewKeyEncodesExactTenantKey(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/stageops/_design/projects/_view/by_theatre", r.URL.Path)
		assert.Equal(t, `"theatre::one"`, r.URL.Query().Get("key"))
		assert.Equal(t, "true", r.URL.Query().Get("include_docs"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"rows":[{"doc":{"_id":"project::one"}}]}`)
	}))
	t.Cleanup(server.Close)
	client := New(Config{BaseURL: server.URL, DB: "stageops"})
	var docs []map[string]interface{}

	err := client.ListByViewKey(context.Background(), "projects", "by_theatre", "theatre::one", &docs)

	require.NoError(t, err)
	require.Len(t, docs, 1)
}
