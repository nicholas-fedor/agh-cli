// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// AuthTestPathLogin is the login endpoint path used by authentication fixtures.
	authTestPathLogin = "/control/login"
	// AuthTestPathLogout is the logout endpoint path used by authentication fixtures.
	authTestPathLogout = "/control/logout"
	// AuthTestUsername is the Basic authentication username for authentication fixtures.
	authTestUsername = "auth-user"
	// AuthTestPassword is the Basic authentication password for authentication fixtures.
	authTestPassword = "auth-password"
	// AuthTestUserAgent is the expected client User-Agent for authentication fixtures.
	authTestUserAgent = "adguard-auth-test/1.0"
	// AuthTestServerURL is the base URL routed by the in-memory transport.
	authTestServerURL = "http://127.0.0.1"
	// AuthTestAdminName is the login name used by authentication fixtures.
	authTestAdminName = "admin"
)

// TestAuthServiceIsImplemented verifies the concrete client satisfies the public
// authentication service contract.
func TestAuthServiceIsImplemented(t *testing.T) {
	t.Parallel()

	client, err := NewClient("http://127.0.0.1")
	require.NoError(t, err)

	var service AuthService = client

	assert.NotNil(t, service)
}

// TestLogin verifies the pinned login request and empty response mode.
func TestLogin(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, authTestUsername, username)
		assert.Equal(t, authTestPassword, password)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, authTestPathLogin, r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, authTestUserAgent, r.Header.Get("User-Agent"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.JSONEq(t, `{"name":"admin","password":"secret"}`, string(body))

		w.WriteHeader(http.StatusOK)

		_, err = io.WriteString(w, "ignored response body")
		assert.NoError(t, err)
	}))
	client := newAuthTestClient(t, server, 4096)

	err := client.Login(t.Context(), Login{
		Name:     authTestAdminName,
		Password: "secret",
	})

	require.NoError(t, err)
}

// TestLoginOmitsEmptyOptionalCredentials verifies a zero Login still sends the
// required JSON object and omits optional empty members.
func TestLoginOmitsEmptyOptionalCredentials(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.JSONEq(t, `{}`, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	client := newAuthTestClient(t, server, 4096)

	err := client.Login(t.Context(), Login{})

	require.NoError(t, err)
}

// TestLoginReturnsStatusError verifies structured login status failures.
func TestLoginReturnsStatusError(t *testing.T) {
	t.Parallel()

	const responseBody = `{"message":"invalid credentials"}`

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newAuthTestClient(t, server, 4096)

	err := client.Login(t.Context(), Login{Name: authTestAdminName, Password: "bad"})

	clientErr := requireAuthError(t, err, ErrorKindStatus)
	assert.Equal(t, "login", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusUnauthorized, clientErr.StatusCode)
	assert.Equal(t, "401 Unauthorized", clientErr.Status)
	assert.JSONEq(t, responseBody, string(clientErr.Body))
}

// TestLoginEnforcesResponseLimit verifies the empty response body is bounded.
func TestLoginEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, strings.Repeat("x", 32))
		assert.NoError(t, err)
	}))
	client := newAuthTestClient(t, server, 8)

	err := client.Login(t.Context(), Login{})

	clientErr := requireAuthError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, "login", clientErr.Operation)
	assert.Equal(t, int64(8), clientErr.Limit)
}

// TestLogoutAcceptsDeclaredRedirect verifies the documented 302 is consumed as
// success and its Location is not followed.
func TestLogoutAcceptsDeclaredRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, authTestUsername, username)
		assert.Equal(t, authTestPassword, password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, authTestPathLogout, r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, authTestUserAgent, r.Header.Get("User-Agent"))
		assert.Empty(t, r.Header.Get("Content-Type"))

		if r.URL.Path == "/complete/logout" {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		w.Header().Set("Location", "/complete/logout")
		w.WriteHeader(http.StatusFound)
	}))
	client := newAuthTestClient(t, server, 4096)

	err := client.Logout(t.Context())

	require.NoError(t, err)
	assert.Zero(t, redirectedRequests.Load())
}

// TestLogoutRejectsUnexpectedRedirect verifies a non-302 redirect is structured
// as a rejected redirect and is not followed.
func TestLogoutRejectsUnexpectedRedirect(t *testing.T) {
	t.Parallel()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/complete/logout" {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		w.Header().Set("Location", "/complete/logout")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	client := newAuthTestClient(t, server, 4096)

	err := client.Logout(t.Context())

	clientErr := requireAuthError(t, err, ErrorKindRedirect)
	assert.Equal(t, "logout", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, "/complete/logout", clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// TestLogoutReturnsStatusError verifies only the declared 302 is successful.
func TestLogoutReturnsStatusError(t *testing.T) {
	t.Parallel()

	const responseBody = "logout unavailable"

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newAuthTestClient(t, server, 4096)

	err := client.Logout(t.Context())

	clientErr := requireAuthError(t, err, ErrorKindStatus)
	assert.Equal(t, "logout", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, responseBody, string(clientErr.Body))
}

// TestLogoutEnforcesResponseLimit verifies redirect success still consumes a
// bounded response body.
func TestLogoutEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "/complete/logout")
		w.WriteHeader(http.StatusFound)

		_, err := io.WriteString(w, strings.Repeat("x", 32))
		assert.NoError(t, err)
	}))
	client := newAuthTestClient(t, server, 8)

	err := client.Logout(t.Context())

	clientErr := requireAuthError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, "logout", clientErr.Operation)
	assert.Equal(t, int64(8), clientErr.Limit)
}

// newAuthTestClient creates a concrete client for auth tests.
func newAuthTestClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *Client {
	t.Helper()

	allOptions := make([]Option, 0, 4)

	allOptions = append(
		allOptions,
		WithHTTPClient(server.Client()),
		WithBasicAuth(authTestUsername, authTestPassword),
		WithUserAgent(authTestUserAgent),
		WithMaxResponseBodySize(limit),
	)

	client, err := NewClient(authTestServerURL, allOptions...)
	require.NoError(t, err)

	return client
}

// requireAuthError extracts and verifies an auth operation error.
func requireAuthError(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}
