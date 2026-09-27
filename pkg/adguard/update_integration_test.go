// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// updateIntegrationRequestCapture contains one captured update request.
type updateIntegrationRequestCapture struct {
	method        string
	path          string
	rawQuery      string
	accept        string
	contentType   string
	contentLength int64
	username      string
	password      string
	userAgent     string
	body          []byte
	readErr       error
	closeErr      error
	hasAuth       bool
}

// updateIntegrationResponseMode describes one successful update response.
type updateIntegrationResponseMode struct {
	name        string
	contentType string
	body        string
	status      int
}

const (
	// The path is the exact begin-update control path.
	updateIntegrationPath = "/api/control/update"
	// The username is the expected Basic authentication username.
	updateIntegrationUsername = "update-integration-user"
	// The password is the expected Basic authentication password.
	updateIntegrationPassword = "update-integration-password"
	// The User-Agent is the expected client User-Agent.
	updateIntegrationUserAgent = "update-integration-client/1.0"
	// The response limit is the default response body limit.
	updateIntegrationResponseLimit int64 = 4096
	// The cancellation timeout bounds cancellation coordination.
	updateIntegrationCancellationTimeout = time.Second
	// The redirect location is the rejected redirect target.
	updateIntegrationRedirectLocation = "http://127.0.0.1/api/update-redirect"
	// The status body is a bounded structured status response.
	updateIntegrationStatusBody = `{"message":"update unavailable"}`
	// The JSON body is an arbitrary successful JSON response body.
	updateIntegrationJSONBody = `{"status":"started"}`
)

// TestUpdateIntegrationRequestContract verifies the authenticated bodyless update request.
func TestUpdateIntegrationRequestContract(t *testing.T) {
	t.Parallel()

	for _, mode := range updateIntegrationResponseModes() {
		t.Run(mode.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan updateIntegrationRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured <- captureUpdateIntegrationRequest(r)

				writeUpdateIntegrationResponse(w, mode.contentType, mode.status, mode.body)
			}))
			client := newUpdateIntegrationClient(t, server)

			err := client.BeginUpdate(t.Context())

			require.NoError(t, err)

			request := <-captured
			assertUpdateIntegrationRequest(t, request)
		})
	}
}

// TestUpdateIntegrationStructuredErrors verifies bounded status, response-limit, and redirect errors.
func TestUpdateIntegrationStructuredErrors(t *testing.T) {
	t.Parallel()

	t.Run("status", func(t *testing.T) {
		t.Parallel()

		server := newUpdateIntegrationResponseServer(
			t,
			"application/problem+json; charset=utf-8",
			http.StatusServiceUnavailable,
			updateIntegrationStatusBody,
		)
		client := newUpdateIntegrationClient(t, server)

		err := client.BeginUpdate(t.Context())

		clientErr := requireUpdateIntegrationError(t, err, adguard.ErrorKindStatus)
		assert.Equal(t, "begin_update", clientErr.Operation)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.Equal(t, http.StatusServiceUnavailable, clientErr.StatusCode)
		assert.Equal(t, "503 Service Unavailable", clientErr.Status)
		assert.Equal(t, "application/problem+json; charset=utf-8", clientErr.ContentType)
		assert.JSONEq(t, updateIntegrationStatusBody, string(clientErr.Body))
	})

	t.Run("response limit", func(t *testing.T) {
		t.Parallel()

		server := newUpdateIntegrationResponseServer(
			t,
			blockedServicesIntegrationJSONContentType,
			http.StatusOK,
			"response exceeds the configured limit",
		)
		limit := int64(8)
		client := newUpdateIntegrationClient(t, server, adguard.WithMaxResponseBodySize(limit))

		err := client.BeginUpdate(t.Context())

		clientErr := requireUpdateIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
		assert.Equal(t, "begin_update", clientErr.Operation)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.Equal(t, http.StatusOK, clientErr.StatusCode)
		//nolint:testifylint // encoded-compare: Content-Type is a media type, not encoded JSON.
		assert.Equal(t, blockedServicesIntegrationJSONContentType, clientErr.ContentType)
		assert.Equal(t, limit, clientErr.Limit)
		assert.Nil(t, clientErr.Body)
	})
}

// TestUpdateIntegrationPropagatesCancellation verifies an in-flight update stops after cancellation.
func TestUpdateIntegrationPropagatesCancellation(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{})
	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if readErr != nil || closeErr != nil {
			return
		}

		close(requestStarted)
		<-r.Context().Done()
	}))
	client := newUpdateIntegrationClient(t, server)
	ctx, cancel := context.WithCancel(t.Context())

	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- client.BeginUpdate(ctx)
	}()

	select {
	case <-requestStarted:
	case <-time.After(updateIntegrationCancellationTimeout):
		cancel()
		t.Fatal("update request did not reach the test server")
	}

	cancel()

	var err error

	select {
	case err = <-result:
	case <-time.After(updateIntegrationCancellationTimeout):
		t.Fatal("update request did not return after cancellation")
	}

	clientErr := requireUpdateIntegrationError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, "begin_update", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestUpdateIntegrationHonorsRequestTimeout verifies the configured request deadline remains matchable.
func TestUpdateIntegrationHonorsRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client := newUpdateIntegrationClient(
		t,
		server,
		adguard.WithRequestTimeout(20*time.Millisecond),
	)

	err := client.BeginUpdate(t.Context())

	clientErr := requireUpdateIntegrationError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, "begin_update", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// TestUpdateIntegrationRejectsRedirect verifies redirects are blocked before forwarding credentials.
func TestUpdateIntegrationRejectsRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/update-redirect" {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		http.Redirect(w, r, updateIntegrationRedirectLocation, http.StatusTemporaryRedirect)
	}))
	client := newUpdateIntegrationClient(t, server)

	err := client.BeginUpdate(t.Context())

	clientErr := requireUpdateIntegrationError(t, err, adguard.ErrorKindRedirect)
	assert.Equal(t, "begin_update", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, updateIntegrationRedirectLocation, clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// updateIntegrationResponseModes returns empty, JSON, and no-content success responses.
//
// Returns:
//   - modes: Successful response variants for the begin-update request.
func updateIntegrationResponseModes() []updateIntegrationResponseMode {
	return []updateIntegrationResponseMode{
		{
			name:   "empty response",
			status: http.StatusOK,
		},
		{
			name:        "JSON response",
			contentType: blockedServicesIntegrationJSONContentType + "; charset=utf-8",
			body:        updateIntegrationJSONBody,
			status:      http.StatusOK,
		},
		{
			name:   "no content",
			status: http.StatusNoContent,
		},
	}
}

// newUpdateIntegrationResponseServer creates a server returning one fixed response.
//
// Parameters:
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP response status.
//   - body: The response body.
//
// Returns:
//   - server: The running test server.
func newUpdateIntegrationResponseServer(
	t *testing.T,
	contentType string,
	status int,
	body string,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeUpdateIntegrationResponse(w, contentType, status, body)
	}))
}

// newUpdateIntegrationClient creates a concrete client for an update test server.
//
// Parameters:
//   - server: The in-memory HTTP test server.
//   - options: Additional client options appended after the test defaults.
//
// Returns:
//   - client: The configured concrete client.
func newUpdateIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	options ...adguard.Option,
) *adguard.Client {
	t.Helper()

	allOptions := make([]adguard.Option, 0, len(options)+4)

	allOptions = append(
		allOptions,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(updateIntegrationUsername, updateIntegrationPassword),
		adguard.WithUserAgent(updateIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(updateIntegrationResponseLimit),
	)
	allOptions = append(allOptions, options...)

	client, err := adguard.NewClient(blockedServicesIntegrationBaseURL, allOptions...)
	require.NoError(t, err)

	return client
}

// captureUpdateIntegrationRequest reads and records one HTTP request.
//
// Parameters:
//   - request: The request received by the test server.
//
// Returns:
//   - capture: The request metadata and body.
func captureUpdateIntegrationRequest(request *http.Request) updateIntegrationRequestCapture {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	username, password, hasAuth := request.BasicAuth()

	return updateIntegrationRequestCapture{
		method:        request.Method,
		path:          request.URL.Path,
		rawQuery:      request.URL.RawQuery,
		accept:        request.Header.Get("Accept"),
		contentType:   request.Header.Get("Content-Type"),
		contentLength: request.ContentLength,
		username:      username,
		password:      password,
		userAgent:     request.Header.Get("User-Agent"),
		body:          body,
		readErr:       readErr,
		closeErr:      closeErr,
		hasAuth:       hasAuth,
	}
}

// assertUpdateIntegrationRequest verifies the exact begin-update request contract.
//
// Parameters:
//   - request: The captured HTTP request.
func assertUpdateIntegrationRequest(t *testing.T, request updateIntegrationRequestCapture) {
	t.Helper()

	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, updateIntegrationPath, request.path)
	assert.Empty(t, request.rawQuery)
	//nolint:testifylint // encoded-compare: Accept is a media type, not encoded JSON.
	assert.Equal(t, blockedServicesIntegrationJSONContentType, request.accept)
	assert.Equal(t, updateIntegrationUserAgent, request.userAgent)
	assert.True(t, request.hasAuth)
	assert.Equal(t, updateIntegrationUsername, request.username)
	assert.Equal(t, updateIntegrationPassword, request.password)
	assert.Zero(t, request.contentLength)
	assert.Empty(t, request.contentType)
	assert.Empty(t, request.body)
}

// requireUpdateIntegrationError extracts a structured client error.
//
// Parameters:
//   - err: The error returned by the client.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted client error.
func requireUpdateIntegrationError(
	t *testing.T,
	err error,
	kind adguard.ErrorKind,
) *adguard.Error {
	t.Helper()

	clientErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}

// writeUpdateIntegrationResponse writes a response while tolerating disconnects.
//
// Parameters:
//   - w: The response writer.
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP response status.
//   - body: The response body.
func writeUpdateIntegrationResponse(w http.ResponseWriter, contentType string, status int, body string) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(status)
	writeUpdateIntegrationBody(w, body)
}

// writeUpdateIntegrationBody writes a response body while tolerating disconnects.
//
// Parameters:
//   - w: The response writer.
//   - body: The response body.
func writeUpdateIntegrationBody(w http.ResponseWriter, body string) {
	if body == "" {
		return
	}

	_, err := w.Write([]byte(body))
	if err != nil {
		return
	}
}
