// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// The exact update endpoint path.
	updateTestPath = "/control/update"
	// The structured error operation name.
	updateTestOperation = "begin_update"
	// The HTTP Basic authentication username.
	updateTestUsername = "update-user"
	// The HTTP Basic authentication password.
	updateTestPassword = "update-password"
	// The configured User-Agent value.
	updateTestAgent = "adguard-update-test/1.0"
)

// TestBeginUpdate verifies the pinned bodyless update request and empty response.
func TestBeginUpdate(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, updateTestUsername, username)
		assert.Equal(t, updateTestPassword, password)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, updateTestPath, r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Zero(t, r.ContentLength)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, updateTestAgent, r.Header.Get("User-Agent"))
		assert.Empty(t, r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Empty(t, body)

		w.WriteHeader(http.StatusOK)
	}))
	client := newUpdateTestClient(t, server, 4096)

	err := client.BeginUpdate(t.Context())

	require.NoError(t, err)
}

// TestBeginUpdateReturnsStatusError verifies bounded non-success response details.
func TestBeginUpdateReturnsStatusError(t *testing.T) {
	t.Parallel()

	const responseBody = "update failed"

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newUpdateTestClient(t, server, 4096)

	err := client.BeginUpdate(t.Context())

	clientErr := requireUpdateError(t, err, ErrorKindStatus)
	assert.Equal(t, updateTestOperation, clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusInternalServerError, clientErr.StatusCode)
	assert.Equal(t, "500 Internal Server Error", clientErr.Status)
	assert.Equal(t, "text/plain; charset=utf-8", clientErr.ContentType)
	assert.Equal(t, responseBody, string(clientErr.Body))
}

// TestBeginUpdateEnforcesResponseLimit verifies successful responses remain bounded.
func TestBeginUpdateEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, strings.Repeat("x", 32))
		assert.NoError(t, err)
	}))
	client := newUpdateTestClient(t, server, 8)

	err := client.BeginUpdate(t.Context())

	clientErr := requireUpdateError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, updateTestOperation, clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, int64(8), clientErr.Limit)
	assert.Nil(t, clientErr.Body)
}

// TestBeginUpdateHonorsRequestTimeout verifies the transport deadline remains matchable.
func TestBeginUpdateHonorsRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client := newUpdateTestClient(
		t,
		server,
		4096,
		WithRequestTimeout(20*time.Millisecond),
	)

	err := client.BeginUpdate(t.Context())

	clientErr := requireUpdateError(t, err, ErrorKindRequest)
	assert.Equal(t, updateTestOperation, clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestBeginUpdateRejectsRedirect verifies redirects are not followed.
func TestBeginUpdateRejectsRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/complete/update" {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		http.Redirect(w, r, "/complete/update", http.StatusTemporaryRedirect)
	}))
	client := newUpdateTestClient(t, server, 4096)

	err := client.BeginUpdate(t.Context())

	clientErr := requireUpdateError(t, err, ErrorKindRedirect)
	assert.Equal(t, updateTestOperation, clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, "http://localhost/complete/update", clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// newUpdateTestClient creates a concrete client bound to an update test server.
//
// Parameters:
//   - t: The test requesting the client.
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum accepted response body size.
//   - options: Additional options that override the test defaults.
//
// Returns:
//   - The configured AdGuard client.
func newUpdateTestClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
	options ...Option,
) *Client {
	t.Helper()

	allOptions := make([]Option, 0, 4+len(options))

	allOptions = append(
		allOptions,
		WithHTTPClient(server.Client()),
		WithBasicAuth(updateTestUsername, updateTestPassword),
		WithUserAgent(updateTestAgent),
		WithMaxResponseBodySize(limit),
	)
	allOptions = append(allOptions, options...)

	client, err := NewClient("http://localhost", allOptions...)
	require.NoError(t, err)

	return client
}

// requireUpdateError extracts and verifies an update operation error.
//
// Parameters:
//   - t: The test inspecting the error.
//   - err: The error returned by BeginUpdate.
//   - kind: The expected structured error kind.
//
// Returns:
//   - The extracted structured client error.
func requireUpdateError(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}
