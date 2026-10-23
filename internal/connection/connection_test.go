// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package connection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// placeheldPassword is a placeholder that client errors must never carry.
const placeheldPassword = "must-not-appear-in-errors"

// TestNewSendsInstanceCredentials verifies the client reaches the configured
// instance and authenticates with its username and password.
func TestNewSendsInstanceCredentials(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/control/clients", r.URL.Path)

		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "user", username)
		assert.Equal(t, "pass", password)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`{"clients":[]}`))
		assert.NoError(t, err)
	}))

	client, err := New(testConfig("http", "user", "pass"), adguard.WithHTTPClient(server.Client()))
	require.NoError(t, err)

	status, err := client.ClientsStatus(t.Context())

	require.NoError(t, err)
	assert.Empty(t, status.Clients)
}

// TestNewOmitsAuthenticationWithoutCredentials verifies an instance configured
// without a username or a password sends no authentication.
func TestNewOmitsAuthenticationWithoutCredentials(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, authenticated := r.BasicAuth()
		assert.False(t, authenticated)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`{"clients":[]}`))
		assert.NoError(t, err)
	}))

	client, err := New(testConfig("http", "", ""), adguard.WithHTTPClient(server.Client()))
	require.NoError(t, err)

	_, err = client.ClientsStatus(t.Context())

	require.NoError(t, err)
}

// TestNewDefaultsToHTTPS verifies an instance without a scheme is reached over
// HTTPS.
//
// The server listens on loopback rather than the in-memory network, because the
// in-memory test client does not trust the certificate of a TLS server.
func TestNewDefaultsToHTTPS(t *testing.T) {
	t.Parallel()

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.NotNil(t, r.TLS)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`{"clients":[]}`))
		assert.NoError(t, err)
	}))
	server.StartTLS()
	t.Cleanup(server.Close)

	cfg := testConfig("", "", "")

	cfg.Host = server.Listener.Addr().String()

	client, err := New(cfg, adguard.WithHTTPClient(server.Client()))
	require.NoError(t, err)

	_, err = client.ClientsStatus(t.Context())

	require.NoError(t, err)
}

// TestNewKeepsPasswordOutOfErrors verifies a configuration error names the
// instance without carrying its password.
func TestNewKeepsPasswordOutOfErrors(t *testing.T) {
	t.Parallel()

	_, err := New(testConfig("http", "user", placeheldPassword), adguard.WithRequestTimeout(0))

	require.Error(t, err)
	assert.Contains(t, err.Error(), `"home"`)
	assert.NotContains(t, err.Error(), placeheldPassword)
}

// testConfig returns an instance configuration for the connection tests.
//
// Parameters:
//   - scheme: transport scheme, or an empty string to use the default.
//   - username: administrator username, or an empty string for none.
//   - password: administrator password, or an empty string for none.
//
// Returns:
//   - instance.Config: the instance configuration.
func testConfig(scheme, username, password string) instance.Config {
	return instance.Config{
		Name:       "home",
		Host:       "127.0.0.1",
		Scheme:     scheme,
		Username:   username,
		Password:   password,
		Credential: nil,
	}
}
