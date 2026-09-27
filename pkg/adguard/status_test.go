// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localTestServerURL is a secure plaintext loopback test base routed by httptest.
const localTestServerURL = "http://localhost"

// validStatusJSON is a complete status response with an unknown future member.
const validStatusJSON = `{
	"dns_addresses": ["127.0.0.1", "::1"],
	"dns_port": 53,
	"http_port": 3000,
	"language": "en",
	"protection_enabled": true,
	"protection_disabled_duration": 0,
	"dhcp_available": true,
	"running": true,
	"version": "v0.107.0",
	"start_time": 1700000000000,
	"future_field": true
}`

// TestClientStatus verifies the successful status contract and request metadata.
func TestClientStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "test-user", username)
		assert.Equal(t, "test-password", password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/status", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "adguard-client-test/1.0", r.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeBody(w, validStatusJSON)
	}))
	client := newTestClient(t, server, "/api/", validStatusJSON)

	status, err := client.Status(t.Context())

	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1", "::1"}, status.DNSAddresses)
	assert.Equal(t, uint16(53), status.DNSPort)
	assert.Equal(t, uint16(3000), status.HTTPPort)
	assert.Equal(t, "en", status.Language)
	assert.True(t, status.ProtectionEnabled)
	require.NotNil(t, status.ProtectionDisabledDuration)
	assert.Zero(t, *status.ProtectionDisabledDuration)
	require.NotNil(t, status.DHCPAvailable)
	assert.True(t, *status.DHCPAvailable)
	assert.True(t, status.Running)
	assert.Equal(t, "v0.107.0", status.Version)
	require.NotNil(t, status.StartTime)
	assert.InDelta(t, float64(1_700_000_000_000), *status.StartTime, 0)
}

// TestClientStatusRequiresBasicAuthentication verifies unauthorized responses.
func TestClientStatusRequiresBasicAuthentication(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, _, authenticated := r.BasicAuth(); !authenticated {
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		writeBody(w, validStatusJSON)
	}))
	httpClient := server.Client()
	client, err := NewClient(localTestServerURL, WithHTTPClient(httpClient))
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindStatus)
	assert.Equal(t, http.StatusUnauthorized, clientErr.StatusCode)
	assert.Equal(t, "unauthorized\n", string(clientErr.Body))
}

// TestClientStatusRejectsNonSuccessStatus verifies structured status errors.
func TestClientStatusRejectsNonSuccessStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusTeapot)
		writeBody(w, "not available")
	}))
	client := newTestClient(t, server, "", validStatusJSON)

	_, err := client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindStatus)
	assert.Equal(t, http.StatusTeapot, clientErr.StatusCode)
	assert.Equal(t, "418 I'm a teapot", clientErr.Status)
	assert.Equal(t, "text/plain; charset=utf-8", clientErr.ContentType)
	assert.Equal(t, "not available", string(clientErr.Body))
}

// TestClientStatusRejectsInvalidJSON verifies strict JSON and schema validation.
func TestClientStatusRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "malformed",
			body: `{"running":`,
		},
		{
			name: "duplicate member",
			body: `{"running":true,"running":false}`,
		},
		{
			name: "missing required member",
			body: `{
				"dns_addresses": ["127.0.0.1"],
				"http_port": 3000,
				"language": "en",
				"protection_enabled": true,
				"running": true,
				"version": "v0.107.0"
			}`,
		},
		{
			name: "invalid required port",
			body: `{
				"dns_addresses": ["127.0.0.1"],
				"dns_port": 0,
				"http_port": 3000,
				"language": "en",
				"protection_enabled": true,
				"running": true,
				"version": "v0.107.0"
			}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				writeBody(w, test.body)
			}))
			client := newTestClient(t, server, "", test.body)

			_, err := client.Status(t.Context())

			clientErr := requireClientError(t, err, ErrorKindJSON)
			assert.Equal(t, string(ErrorKindStatus), clientErr.Operation)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestClientStatusRejectsWrongContentType verifies successful media type validation.
func TestClientStatusRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, validStatusJSON)
	}))
	client := newTestClient(t, server, "", validStatusJSON)

	_, err := client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindContentType)
	assert.Equal(t, "text/plain", clientErr.ContentType)
}

// TestClientStatusRejectsOversizedBody verifies the configured response bound.
func TestClientStatusRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, validStatusJSON)
	}))
	httpClient := server.Client()
	client, err := NewClient(
		localTestServerURL,
		WithHTTPClient(httpClient),
		WithBasicAuth("test-user", "test-password"),
		WithMaxResponseBodySize(int64(len(validStatusJSON))-1),
	)
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, int64(len(validStatusJSON))-1, clientErr.Limit)
}

// TestClientStatusHonorsRequestTimeout verifies per-request deadline handling.
func TestClientStatusHonorsRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	httpClient := server.Client()
	client, err := NewClient(
		localTestServerURL,
		WithHTTPClient(httpClient),
		WithRequestTimeout(20*time.Millisecond),
	)
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, string(ErrorKindStatus), clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestClientStatusHonorsCancellation verifies context cancellation propagation.
func TestClientStatusHonorsCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, validStatusJSON)
	}))
	client := newTestClient(t, server, "", validStatusJSON)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.Status(ctx)

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, string(ErrorKindStatus), clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestClientStatusRejectsRedirects verifies redirects are never followed.
func TestClientStatusRejectsRedirects(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/complete/status" {
			redirectedRequests.Add(1)
			w.Header().Set("Content-Type", "application/json")
			writeBody(w, validStatusJSON)

			return
		}

		http.Redirect(w, r, "/complete/status", http.StatusTemporaryRedirect)
	}))
	httpClient := server.Client()
	client, err := NewClient(
		localTestServerURL,
		WithHTTPClient(httpClient),
		WithBasicAuth("test-user", "test-password"),
	)
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindRedirect)
	assert.Equal(t, localTestServerURL+"/complete/status", clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// writeBody writes a test response body while tolerating client disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeBody(w http.ResponseWriter, body string) {
	_, err := w.Write([]byte(body))
	if err != nil {
		return
	}
}

// newTestClient creates a status client bound to an in-memory test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - basePath: The API path prepended to the local test server URL.
//   - body: The response body used to configure the response limit.
//
// Returns:
//   - client: The configured AdGuard client.
func newTestClient(
	t *testing.T,
	server *httptest.Server,
	basePath string,
	body string,
) *Client {
	t.Helper()

	httpClient := server.Client()
	client, err := NewClient(
		localTestServerURL+basePath,
		WithHTTPClient(httpClient),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-client-test/1.0"),
		WithMaxResponseBodySize(int64(len(body))),
	)
	require.NoError(t, err)

	return client
}

// requireClientError extracts and verifies a structured client error.
//
// Parameters:
//   - err: The error to inspect.
//   - kind: The expected client error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireClientError(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}
