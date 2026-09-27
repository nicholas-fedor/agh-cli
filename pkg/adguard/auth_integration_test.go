// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

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

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// Auth integration tests use fixed credentials and bounded response settings.
const (
	authIntegrationLoginPath       = "/control/login"
	authIntegrationLogoutPath      = "/control/logout"
	authIntegrationRedirectPath    = "/complete/logout"
	authIntegrationUsername        = "auth-integration-user"
	authIntegrationPassword        = "auth-integration-password"
	authIntegrationUserAgent       = "adguard-auth-integration-test/1.0"
	authIntegrationResponseLimit   = int64(4096)
	authIntegrationCancellationTTL = time.Second
	adguardIntegrationAdminName    = "admin"
)

// TestAuthIntegrationLoginUsesEmptyResponseMode verifies credential presence and opaque successful responses.
func TestAuthIntegrationLoginUsesEmptyResponseMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		request  adguard.Login
		wantBody string
	}{
		{
			name:     "omitted credentials",
			request:  adguard.Login{},
			wantBody: `{}`,
		},
		{
			name: "present credentials",
			request: adguard.Login{
				Name:     adguardIntegrationAdminName,
				Password: "secret",
			},
			wantBody: `{"name":"admin","password":"secret"}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertAuthIntegrationRequest(t, r, http.MethodPost, authIntegrationLoginPath)

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.JSONEq(t, test.wantBody, string(body))

				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)

				_, err = io.WriteString(w, "opaque login response")
				assert.NoError(t, err)
			}))
			client := newAuthIntegrationClient(t, server)

			err := client.Login(t.Context(), test.request)

			require.NoError(t, err)
		})
	}
}

// TestAuthIntegrationLoginRejectsRedirect verifies redirects are not followed.
func TestAuthIntegrationLoginRejectsRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == authIntegrationRedirectPath {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		assertAuthIntegrationRequest(t, r, http.MethodPost, authIntegrationLoginPath)

		w.Header().Set("Location", authIntegrationRedirectPath)
		w.WriteHeader(http.StatusFound)
	}))
	client := newAuthIntegrationClient(t, server)

	err := client.Login(t.Context(), adguard.Login{Name: "admin", Password: "secret"})

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindRedirect)
	assert.Equal(t, "login", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, localTestServerURL+authIntegrationRedirectPath, clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// TestAuthIntegrationLoginReturnsStructuredStatusError verifies non-success metadata is retained.
func TestAuthIntegrationLoginReturnsStructuredStatusError(t *testing.T) {
	t.Parallel()

	const responseBody = `{"message":"invalid credentials"}`

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthIntegrationRequest(t, r, http.MethodPost, authIntegrationLoginPath)

		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newAuthIntegrationClient(t, server)

	err := client.Login(t.Context(), adguard.Login{Name: "admin", Password: "bad"})

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, "login", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusUnauthorized, clientErr.StatusCode)
	assert.Equal(t, "401 Unauthorized", clientErr.Status)
	assert.Equal(t, "application/problem+json", clientErr.ContentType)
	assert.JSONEq(t, responseBody, string(clientErr.Body))
}

// TestAuthIntegrationLoginRejectsMalformedInput verifies encoding failures occur before transport.
func TestAuthIntegrationLoginRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	client := newAuthIntegrationClient(t, server)

	err := client.Login(t.Context(), adguard.Login{Name: string([]byte{0xff})})

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, "login", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	require.ErrorContains(t, err, "encode request")
	assert.Zero(t, requests.Load())
}

// TestAuthIntegrationLoginEnforcesResponseLimit verifies opaque bodies remain bounded.
func TestAuthIntegrationLoginEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthIntegrationRequest(t, r, http.MethodPost, authIntegrationLoginPath)

		_, err := io.WriteString(w, strings.Repeat("x", 32))
		assert.NoError(t, err)
	}))
	client := newAuthIntegrationClient(t, server, adguard.WithMaxResponseBodySize(8))

	err := client.Login(t.Context(), adguard.Login{})

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
	assert.Equal(t, "login", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, int64(8), clientErr.Limit)
	assert.Empty(t, clientErr.Body)
}

// TestAuthIntegrationLogoutAcceptsDeclaredRedirect verifies the declared 302 succeeds without forwarding credentials.
func TestAuthIntegrationLogoutAcceptsDeclaredRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == authIntegrationRedirectPath {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		assertAuthIntegrationRequest(t, r, http.MethodGet, authIntegrationLogoutPath)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Location", authIntegrationRedirectPath)
		w.WriteHeader(http.StatusFound)

		_, err := io.WriteString(w, "opaque redirect body")
		assert.NoError(t, err)
	}))
	client := newAuthIntegrationClient(t, server)

	err := client.Logout(t.Context())

	require.NoError(t, err)
	assert.Zero(t, redirectedRequests.Load())
}

// TestAuthIntegrationLogoutRejectsUnexpectedRedirect verifies other 3xx responses remain structured.
func TestAuthIntegrationLogoutRejectsUnexpectedRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == authIntegrationRedirectPath {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		assertAuthIntegrationRequest(t, r, http.MethodGet, authIntegrationLogoutPath)

		w.Header().Set("Location", authIntegrationRedirectPath)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	client := newAuthIntegrationClient(t, server)

	err := client.Logout(t.Context())

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindRedirect)
	assert.Equal(t, "logout", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, authIntegrationRedirectPath, clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// TestAuthIntegrationLogoutRejectsSuccessfulStatus verifies only 302 is accepted.
func TestAuthIntegrationLogoutRejectsSuccessfulStatus(t *testing.T) {
	t.Parallel()

	const responseBody = "logout is not available"

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthIntegrationRequest(t, r, http.MethodGet, authIntegrationLogoutPath)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newAuthIntegrationClient(t, server)

	err := client.Logout(t.Context())

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, "logout", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, responseBody, string(clientErr.Body))
}

// TestAuthIntegrationLogoutEnforcesResponseLimit verifies declared redirects still have bounded bodies.
func TestAuthIntegrationLogoutEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertAuthIntegrationRequest(t, r, http.MethodGet, authIntegrationLogoutPath)

		w.Header().Set("Location", authIntegrationRedirectPath)
		w.WriteHeader(http.StatusFound)

		_, err := io.WriteString(w, strings.Repeat("x", 32))
		assert.NoError(t, err)
	}))
	client := newAuthIntegrationClient(t, server, adguard.WithMaxResponseBodySize(8))

	err := client.Logout(t.Context())

	clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
	assert.Equal(t, "logout", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusFound, clientErr.StatusCode)
	assert.Equal(t, int64(8), clientErr.Limit)
	assert.Empty(t, clientErr.Body)
}

// TestAuthIntegrationHonorsCancellation verifies in-flight login and logout cancellation remains matchable.
func TestAuthIntegrationHonorsCancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		method    string
		path      string
		operation string
		invoke    func(context.Context, *adguard.Client) error
	}{
		{
			name:      "login",
			method:    http.MethodPost,
			path:      authIntegrationLoginPath,
			operation: "login",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.Login(ctx, adguard.Login{})
			},
		},
		{
			name:      "logout",
			method:    http.MethodGet,
			path:      authIntegrationLogoutPath,
			operation: "logout",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.Logout(ctx)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requestStarted := make(chan struct{})
			releaseHandler := make(chan struct{})
			server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				assertAuthIntegrationRequest(t, r, test.method, test.path)
				close(requestStarted)
				<-releaseHandler
			}))
			client := newAuthIntegrationClient(t, server)
			ctx, cancel := context.WithCancel(t.Context())

			defer cancel()
			defer close(releaseHandler)

			result := make(chan error, 1)

			go func() {
				result <- test.invoke(ctx, client)
			}()

			waitForAuthIntegrationRequest(t, requestStarted)
			cancel()

			err := waitForAuthIntegrationResult(t, result)

			clientErr := requireAuthIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

// waitForAuthIntegrationRequest waits for the test server to receive a request.
//
// Parameters:
//   - requestStarted: The channel closed when the handler receives a request.
func waitForAuthIntegrationRequest(t *testing.T, requestStarted <-chan struct{}) {
	t.Helper()

	select {
	case <-requestStarted:
	case <-time.After(authIntegrationCancellationTTL):
		t.Fatal("authentication request did not reach the test server")
	}
}

// waitForAuthIntegrationResult waits for a canceled client call to return.
//
// Parameters:
//   - result: The channel receiving the client call result.
//
// Returns:
//   - The error returned by the canceled client call.
func waitForAuthIntegrationResult(t *testing.T, result <-chan error) error {
	t.Helper()

	var err error

	select {
	case err = <-result:
	case <-time.After(authIntegrationCancellationTTL):
		t.Fatal("authentication request did not return after cancellation")
	}

	return err
}

// newAuthIntegrationClient creates a concrete authenticated client for a test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - options: Additional client options applied after the integration defaults.
//
// Returns:
//   - The configured AdGuard client.
func newAuthIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	options ...adguard.Option,
) *adguard.Client {
	t.Helper()

	allOptions := make([]adguard.Option, 0, 4+len(options))

	allOptions = append(
		allOptions,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(authIntegrationUsername, authIntegrationPassword),
		adguard.WithUserAgent(authIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(authIntegrationResponseLimit),
	)
	allOptions = append(allOptions, options...)

	client, err := adguard.NewClient(localTestServerURL, allOptions...)
	require.NoError(t, err)

	return client
}

// assertAuthIntegrationRequest verifies the exact authenticated request metadata.
//
// Parameters:
//   - request: The request received by the test server.
//   - method: The expected HTTP method.
//   - path: The expected request path.
func assertAuthIntegrationRequest(t *testing.T, request *http.Request, method, path string) {
	t.Helper()

	username, password, authenticated := request.BasicAuth()
	assert.True(t, authenticated)
	assert.Equal(t, authIntegrationUsername, username)
	assert.Equal(t, authIntegrationPassword, password)
	assert.Equal(t, method, request.Method)
	assert.Equal(t, path, request.URL.Path)
	assert.Empty(t, request.URL.RawQuery)
	assert.Equal(t, "application/json", request.Header.Get("Accept"))
	assert.Equal(t, authIntegrationUserAgent, request.Header.Get("User-Agent"))

	if method == http.MethodGet {
		assert.Zero(t, request.ContentLength)
		assert.Empty(t, request.Header.Get("Content-Type"))

		return
	}

	assert.Positive(t, request.ContentLength)
	assert.Equal(t, "application/json", request.Header.Get("Content-Type"))
}

// requireAuthIntegrationError extracts and verifies a structured authentication error.
//
// Parameters:
//   - err: The error returned by an authentication operation.
//   - kind: The expected structured error kind.
//
// Returns:
//   - The extracted structured client error.
func requireAuthIntegrationError(
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
