package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/stageops/backend/internal/couch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadinessHandlerChecksCouchDB(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		couchStatus    int
		expectedStatus int
	}{
		{name: "ready", couchStatus: http.StatusOK, expectedStatus: http.StatusOK},
		{name: "unavailable", couchStatus: http.StatusInternalServerError, expectedStatus: http.StatusServiceUnavailable},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.couchStatus)
			}))
			defer server.Close()

			app := fiber.New()
			app.Get("/ready", readinessHandler(couch.New(couch.Config{BaseURL: server.URL})))

			response, err := app.Test(httptest.NewRequest(http.MethodGet, "/ready", nil))
			require.NoError(t, err)
			assert.Equal(t, test.expectedStatus, response.StatusCode)
		})
	}
}
