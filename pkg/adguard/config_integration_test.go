// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

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

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// roundTripFunc adapts a function to [http.RoundTripper].
type roundTripFunc func(*http.Request) (*http.Response, error)

const (
	// The localTestServerURL constant is a secure plaintext loopback test base
	// routed by httptest.
	localTestServerURL = "http://localhost"
	// The configIntegrationProblemBody fixture is a bounded non-success body.
	configIntegrationProblemBody = `{"message":"configuration endpoint unavailable"}`
	// The validStatusJSON fixture is a complete status response with an unknown future member.
	validStatusJSON = `{
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
)

var _ http.RoundTripper = roundTripFunc(nil)

// TestClientConfigurationIntegration exercises configured requests through the public status operation.
func TestClientConfigurationIntegration(t *testing.T) {
	t.Parallel()

	var transportCalls atomic.Int64

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, "config-user", username)
		assert.Equal(t, "config-password", password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/root/control/status", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "adguard-config-test/1.0", r.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeBody(w, validStatusJSON)
	}))

	httpClient := *server.Client()
	baseTransport := httpClient.Transport
	require.NotNil(t, baseTransport)

	httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		transportCalls.Add(1)

		return baseTransport.RoundTrip(request)
	})

	client, err := adguard.NewClient(
		localTestServerURL+"/api/root/",
		adguard.WithHTTPClient(&httpClient),
		adguard.WithBasicAuth("config-user", "config-password"),
		adguard.WithUserAgent("adguard-config-test/1.0"),
		adguard.WithMaxResponseBodySize(int64(len(validStatusJSON))),
	)
	require.NoError(t, err)

	status, err := client.Status(t.Context())

	require.NoError(t, err)
	assert.Equal(t, "v0.107.0", status.Version)
	assert.Equal(t, int64(1), transportCalls.Load())
}

// TestClientConfigurationIntegrationBoundsRequests verifies the configured request timeout reaches the
// server operation.
func TestClientConfigurationIntegrationBoundsRequests(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))

	client, err := adguard.NewClient(
		localTestServerURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithRequestTimeout(50*time.Millisecond),
	)
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, string(adguard.ErrorKindStatus), clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestClientConfigurationIntegrationEnforcesResponseLimit verifies oversized responses fail with
// bounded-response metadata.
func TestClientConfigurationIntegrationEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	limit := int64(len(validStatusJSON) - 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, validStatusJSON)
	}))

	client, err := adguard.NewClient(
		localTestServerURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, adguard.ErrorKindResponseTooLarge)
	assert.Equal(t, string(adguard.ErrorKindStatus), clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, limit, clientErr.Limit)
	assert.Empty(t, clientErr.Body)
}

// TestClientConfigurationIntegrationClassifiesErrors exposes configuration and HTTP failures as
// structured client errors.
func TestClientConfigurationIntegrationClassifiesErrors(t *testing.T) {
	t.Parallel()

	t.Run("configuration", func(t *testing.T) {
		t.Parallel()

		client, err := adguard.NewClient("https://example.test", nil)

		require.Nil(t, client)

		clientErr := requireClientError(t, err, adguard.ErrorKindConfig)
		assert.Empty(t, clientErr.Operation)
		assert.Zero(t, clientErr.StatusCode)
		assert.ErrorContains(t, err, "option must not be nil")
	})

	t.Run("status", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/problem+json")
			w.WriteHeader(http.StatusServiceUnavailable)
			writeBody(w, configIntegrationProblemBody)
		}))

		client, err := adguard.NewClient(
			localTestServerURL+"/api/",
			adguard.WithHTTPClient(server.Client()),
			adguard.WithMaxResponseBodySize(int64(len(configIntegrationProblemBody))),
		)
		require.NoError(t, err)

		_, err = client.Status(t.Context())

		clientErr := requireClientError(t, err, adguard.ErrorKindStatus)
		assert.Equal(t, string(adguard.ErrorKindStatus), clientErr.Operation)
		assert.Equal(t, http.MethodGet, clientErr.Method)
		assert.Equal(t, http.StatusServiceUnavailable, clientErr.StatusCode)
		assert.Equal(t, "503 Service Unavailable", clientErr.Status)
		assert.Equal(t, "application/problem+json", clientErr.ContentType)
		assert.JSONEq(t, configIntegrationProblemBody, string(clientErr.Body))
	})
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

// RoundTrip executes the configured round-trip function.
//
// Parameters:
//   - request: The HTTP request to pass to the configured function.
//
// Returns:
//   - response: The HTTP response returned by the configured function.
//   - err: The error returned by the configured function.
func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

// requireClientError extracts and verifies a structured client error.
//
// Parameters:
//   - err: The error to inspect.
//   - kind: The expected client error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireClientError(t *testing.T, err error, kind adguard.ErrorKind) *adguard.Error {
	t.Helper()

	clientErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}
