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

const (
	// ValidProfileJSON is a complete profile response.
	validProfileJSON = `{"name":"admin","language":"en","theme":"dark"}`
)

// TestClientGetProfile verifies the profile response contract.
func TestClientGetProfile(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/profile", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, validProfileJSON)
	}))
	client := newProfileTestClient(t, server, 4096)

	profile, err := client.GetProfile(t.Context())

	require.NoError(t, err)
	assert.Equal(t, Profile{Name: authTestAdminName, Language: "en", Theme: "dark"}, *profile)
}

// TestClientUpdateProfile verifies the pinned PUT path and complete request body.
func TestClientUpdateProfile(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPut, r.Method)
		assert.Equal(t, "/api/control/profile/update", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)

		var body map[string]any

		decodeProfileRequestBody(t, r, &body)
		assert.Equal(t, "operator", body["name"])
		assert.Equal(t, "de", body["language"])
		assert.Equal(t, "light", body["theme"])

		w.WriteHeader(http.StatusOK)
	}))
	client := newProfileTestClient(t, server, 4096)

	err := client.UpdateProfile(t.Context(), Profile{
		Name:     "operator",
		Language: "de",
		Theme:    "light",
	})

	require.NoError(t, err)
}

// TestClientProfileContentType verifies successful media type enforcement.
func TestClientProfileContentType(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, validProfileJSON)
	}))
	client := newProfileTestClient(t, server, 4096)

	_, err := client.GetProfile(t.Context())

	clientErr := requireClientError(t, err, ErrorKindContentType)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, "text/plain", clientErr.ContentType)
}

// TestClientProfileResponseLimit verifies response bounds on profile responses.
func TestClientProfileResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, validProfileJSON)
	}))
	client := newProfileTestClient(t, server, int64(len(validProfileJSON))-1)

	_, err := client.GetProfile(t.Context())

	clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, int64(len(validProfileJSON))-1, clientErr.Limit)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
}

// TestClientProfileRequiredResponseFields verifies missing profile members fail.
func TestClientProfileRequiredResponseFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"name":"admin","language":"en"}`)
	}))
	client := newProfileTestClient(t, server, 4096)

	_, err := client.GetProfile(t.Context())

	clientErr := requireClientError(t, err, ErrorKindJSON)
	assert.Equal(t, "get_profile", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
}

// newProfileTestClient creates a client bound to a profile test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newProfileTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-profile-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// decodeProfileRequestBody decodes a JSON request body for assertions.
//
// Parameters:
//   - r: The request whose body should be decoded.
//   - result: The destination for the decoded JSON body.
func decodeProfileRequestBody(t *testing.T, r *http.Request, result any) {
	t.Helper()

	payload, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, result))
}
