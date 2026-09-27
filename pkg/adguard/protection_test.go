// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClientSetProtection verifies required and optional protection request fields.
func TestClientSetProtection(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		duration         *uint64
		expectDuration   bool
		expectedDuration any
	}{
		"duration omitted": {
			duration:         nil,
			expectDuration:   false,
			expectedDuration: nil,
		},
		"explicit zero value": {
			duration:         new(uint64(0)),
			expectDuration:   true,
			expectedDuration: float64(0),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/api/control/protection", r.URL.Path)
				assert.Empty(t, r.URL.RawQuery)

				var body map[string]any

				decodeProtectionRequestBody(t, r, &body)
				assert.Equal(t, false, body["enabled"])

				_, exists := body["duration"]
				assert.Equal(t, test.expectDuration, exists)
				assert.Equal(t, test.expectedDuration, body["duration"])

				w.WriteHeader(http.StatusOK)
			}))
			client := newProtectionTestClient(t, server, 4096)

			err := client.SetProtection(t.Context(), ProtectionConfig{
				Enabled:  false,
				Duration: test.duration,
			})

			require.NoError(t, err)
		})
	}
}

// TestClientClearCache verifies the bodyless POST and bare empty 200 response.
func TestClientClearCache(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/control/cache_clear", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, int64(0), r.ContentLength)
		assert.Empty(t, r.Header.Get("Content-Type"))
		w.WriteHeader(http.StatusOK)
	}))
	client := newProtectionTestClient(t, server, 4096)

	err := client.ClearCache(t.Context())

	require.NoError(t, err)
}

// newProtectionTestClient creates a client bound to a protection test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newProtectionTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-protection-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// decodeProtectionRequestBody decodes a JSON request body for assertions.
//
// Parameters:
//   - r: The request whose body should be decoded.
//   - result: The destination for the decoded JSON body.
func decodeProtectionRequestBody(t *testing.T, r *http.Request, result any) {
	t.Helper()

	payload, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, result))
}
