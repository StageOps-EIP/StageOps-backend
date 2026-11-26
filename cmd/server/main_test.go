package main

import (
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stageops/backend/internal/couch"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEnvBool(t *testing.T) {
	t.Setenv("FEATURE_FLAG", "false")
	assert.False(t, envBool("FEATURE_FLAG", true))
	t.Setenv("MISSING_FEATURE_FLAG", "")
	assert.True(t, envBool("MISSING_FEATURE_FLAG", true))
}

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

func TestGlobalErrorHandlerPreservesRequestErrors(t *testing.T) {
	app := fiber.New(fiber.Config{
		BodyLimit: 16, DisableStartupMessage: true, ErrorHandler: globalErrorHandler,
	})
	app.Post("/resource", func(c *fiber.Ctx) error {
		return errors.New("private failure details")
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	serveResult := make(chan error, 1)
	go func() { serveResult <- app.Listener(listener) }()
	t.Cleanup(func() {
		assert.NoError(t, app.ShutdownWithTimeout(5*time.Second))
		assert.NoError(t, <-serveResult)
	})
	client := &http.Client{Timeout: 5 * time.Second}

	tests := []struct {
		name, method, path, body string
		status                   int
		code                     string
	}{
		{name: "unknown route", method: http.MethodGet, path: "/unknown", status: 404, code: "NOT_FOUND"},
		{name: "wrong method", method: http.MethodGet, path: "/resource", status: 405, code: "METHOD_NOT_ALLOWED"},
		{name: "large body", method: http.MethodPost, path: "/resource", body: strings.Repeat("a", 17), status: 413, code: "PAYLOAD_TOO_LARGE"},
		{name: "internal error", method: http.MethodPost, path: "/resource", status: 500, code: "INTERNAL_ERROR"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(test.method, "http://"+listener.Addr().String()+test.path,
				strings.NewReader(test.body))
			require.NoError(t, err)
			response, err := client.Do(request)
			require.NoError(t, err)
			defer response.Body.Close()
			assert.Equal(t, test.status, response.StatusCode)
			var envelope struct {
				Error struct {
					Code    string
					Message string
				}
			}
			require.NoError(t, json.NewDecoder(response.Body).Decode(&envelope))
			assert.Equal(t, test.code, envelope.Error.Code)
			assert.NotContains(t, envelope.Error.Message, "private failure details")
		})
	}
}
