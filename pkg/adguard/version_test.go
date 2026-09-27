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

// TestClientGetVersionInfo verifies the required body and optional boolean presence.
func TestClientGetVersionInfo(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		recheckNow    *bool
		expectRecheck bool
		expectedValue any
	}{
		"omitted": {
			recheckNow:    nil,
			expectRecheck: false,
			expectedValue: nil,
		},
		"explicit false": {
			recheckNow:    new(false),
			expectRecheck: true,
			expectedValue: false,
		},
		"explicit true": {
			recheckNow:    new(true),
			expectRecheck: true,
			expectedValue: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/api/control/version.json", r.URL.Path)
				assert.Empty(t, r.URL.RawQuery)

				var body map[string]any

				decodeVersionRequestBody(t, r, &body)

				recheck, exists := body["recheck_now"]
				assert.Equal(t, test.expectRecheck, exists)
				assert.Equal(t, test.expectedValue, recheck)

				w.Header().Set("Content-Type", "application/json")
				writeBody(w, `{
					"disabled": false,
					"new_version": "v0.108.0",
					"announcement": null,
					"can_autoupdate": false
				}`)
			}))
			client := newVersionTestClient(t, server, 4096)

			versionInfo, err := client.GetVersionInfo(t.Context(), test.recheckNow)

			require.NoError(t, err)
			assert.False(t, versionInfo.Disabled)
			require.NotNil(t, versionInfo.NewVersion)
			assert.Equal(t, "v0.108.0", *versionInfo.NewVersion)
			assert.Nil(t, versionInfo.Announcement)
			require.NotNil(t, versionInfo.CanAutoupdate)
			assert.False(t, *versionInfo.CanAutoupdate)
		})
	}
}

// TestClientVersionRequiredResponseFields verifies a missing disabled field fails.
func TestClientVersionRequiredResponseFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"new_version":"v0.108.0"}`)
	}))
	client := newVersionTestClient(t, server, 4096)

	_, err := client.GetVersionInfo(t.Context(), nil)

	clientErr := requireClientError(t, err, ErrorKindJSON)
	assert.Equal(t, "get_version_info", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
}

// newVersionTestClient creates a client bound to a version test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newVersionTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-version-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// decodeVersionRequestBody decodes a JSON request body for assertions.
//
// Parameters:
//   - r: The request whose body should be decoded.
//   - result: The destination for the decoded JSON body.
func decodeVersionRequestBody(t *testing.T, r *http.Request, result any) {
	t.Helper()

	payload, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, result))
}
