// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientsMutationCase describes one mutation request contract.
type clientsMutationCase struct {
	name      string
	path      string
	wantBody  string
	operation func(context.Context, *Client) error
}

// clientsRequestCapture carries a handler body read back to the test goroutine.
type clientsRequestCapture struct {
	body string
	err  error
}

const (
	// ClientsTestName is the shared client name used by request-contract tests.
	clientsTestName = "desk"
	// ClientsTestClientID is the shared client identifier used by request-contract tests.
	clientsTestClientID = "192.0.2.1"
	// ClientsTestBlockedHost is the shared blocked host used by access-list tests.
	clientsTestBlockedHost = "ads.example"
	// ClientsAddTestName is the shared add-operation name used by request-contract tests.
	clientsAddTestName = "add"
	// ClientsUpdateTestName is the shared update-operation name used by request-contract tests.
	clientsUpdateTestName = "update"
)

// TestClientsStatus verifies configured and discovered client decoding.
func TestClientsStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "test-user", username)
		assert.Equal(t, "test-password", password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/clients", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"clients":[{"name":"desk","ids":["192.0.2.1"],"filtering_enabled":true}],`+
			`"auto_clients":[{"ip":"192.0.2.2","name":"laptop","source":"arp"}],`+
			`"supported_tags":["trusted"]}`)
	}))
	client := newClientsClient(t, server, 1024)

	status, err := client.ClientsStatus(t.Context())

	require.NoError(t, err)
	require.Len(t, status.Clients, 1)
	assert.Equal(t, clientsTestName, status.Clients[0].Name)
	assert.True(t, status.Clients[0].FilteringEnabled)
	require.Len(t, status.AutoClients, 1)
	assert.Equal(t, "laptop", status.AutoClients[0].Name)
	assert.Equal(t, []string{"trusted"}, status.SupportedTags)
}

// TestClientsMutationsSendExactJSONAndAcceptEmptySuccess verifies each mutation wire contract.
func TestClientsMutationsSendExactJSONAndAcceptEmptySuccess(t *testing.T) {
	t.Parallel()

	for _, test := range clientsMutationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan clientsRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, test.path, r.URL.Path)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				body, err := io.ReadAll(r.Body)
				captured <- clientsRequestCapture{body: string(body), err: err}

				w.WriteHeader(http.StatusOK)
			}))
			client := newClientsClient(t, server, 1024)

			require.NoError(t, test.operation(t.Context(), client))

			request := <-captured
			require.NoError(t, request.err)
			assert.Equal(t, test.wantBody, request.body)
		})
	}
}

// clientsMutationCases returns independent mutation request contracts.
//
// Returns:
//   - The client, access, and update mutation cases.
func clientsMutationCases() []clientsMutationCase {
	enabled := true
	disabled := false
	update := ClientUpdate{
		Name: clientsTestName,
		Data: newClientsUpdateData(&disabled, &enabled),
	}

	return []clientsMutationCase{
		{
			name:     clientsAddTestName,
			path:     "/control/clients/add",
			wantBody: `{"name":"desk","ids":["192.0.2.1"],"filtering_enabled":true}`,
			operation: func(ctx context.Context, client *Client) error {
				return client.ClientsAdd(ctx, newClientsAddConfig())
			},
		},
		{
			name:      "delete",
			path:      "/control/clients/delete",
			wantBody:  `{"name":"desk"}`,
			operation: clientsDeleteOperation(),
		},
		{
			name:     clientsUpdateTestName,
			path:     "/control/clients/update",
			wantBody: `{"name":"desk","data":{"use_global_settings":true,"filtering_enabled":false}}`,
			operation: func(ctx context.Context, client *Client) error {
				return client.ClientsUpdate(ctx, update)
			},
		},
		{
			name: "access set",
			path: "/control/access/set",
			wantBody: `{"allowed_clients":["192.0.2.1"],"disallowed_clients":["198.51.100.1"],` +
				`"blocked_hosts":["ads.example"]}`,
			operation: clientsAccessSetOperation(),
		},
	}
}

// clientsDeleteOperation returns the delete mutation operation.
//
// Returns:
//   - A function that deletes the shared test client.
func clientsDeleteOperation() func(context.Context, *Client) error {
	return func(ctx context.Context, client *Client) error {
		return client.ClientsDelete(ctx, ClientDelete{Name: clientsTestName})
	}
}

// clientsAccessSetOperation returns the access replacement operation.
//
// Returns:
//   - A function that replaces the shared test access list.
func clientsAccessSetOperation() func(context.Context, *Client) error {
	return func(ctx context.Context, client *Client) error {
		return client.AccessSet(ctx, AccessList{
			AllowedClients:    []string{clientsTestClientID},
			DisallowedClients: []string{"198.51.100.1"},
			BlockedHosts:      []string{clientsTestBlockedHost},
		})
	}
}

// TestClientsUpdatePreservesFieldPresence verifies omitted and explicit update values.
func TestClientsUpdatePreservesFieldPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     *ClientUpdateData
		wantBody string
	}{
		{
			name:     "nil fields",
			data:     newClientsUpdateData(nil, nil),
			wantBody: `{"name":"desk","data":{}}`,
		},
		{
			name: "explicit empty and zero values",
			data: &ClientUpdateData{
				Name:                     new(""),
				IDs:                      new([]string{}),
				UseGlobalSettings:        new(false),
				FilteringEnabled:         new(false),
				ParentalEnabled:          new(false),
				SafebrowsingEnabled:      new(false),
				SafesearchEnabled:        new(false),
				SafeSearch:               &SafeSearchConfig{},
				UseGlobalBlockedServices: new(false),
				BlockedServicesSchedule:  new(map[string]any{}),
				BlockedServices:          new([]string{}),
				Upstreams:                new([]string{}),
				Tags:                     new([]string{}),
				IgnoreQuerylog:           new(false),
				IgnoreStatistics:         new(false),
				UpstreamsCacheEnabled:    new(false),
				UpstreamsCacheSize:       new(int64(0)),
			},
			wantBody: `{"name":"desk","data":{"name":"","ids":[],` +
				`"use_global_settings":false,"filtering_enabled":false,` +
				`"parental_enabled":false,"safebrowsing_enabled":false,` +
				`"safesearch_enabled":false,"safe_search":{},` +
				`"use_global_blocked_services":false,"blocked_services_schedule":{},` +
				`"blocked_services":[],"upstreams":[],"tags":[],` +
				`"ignore_querylog":false,"ignore_statistics":false,` +
				`"upstreams_cache_enabled":false,"upstreams_cache_size":0}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan clientsRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, err := io.ReadAll(r.Body)
				captured <- clientsRequestCapture{body: string(body), err: err}

				w.WriteHeader(http.StatusOK)
			}))
			client := newClientsClient(t, server, 1024)

			err := client.ClientsUpdate(t.Context(), ClientUpdate{
				Name: clientsTestName,
				Data: test.data,
			})

			require.NoError(t, err)

			request := <-captured
			require.NoError(t, request.err)
			assert.JSONEq(t, test.wantBody, request.body)
		})
	}
}

// TestClientsSearchAndFind verifies exact-match search and legacy lookup decoding.
func TestClientsSearchAndFind(t *testing.T) {
	t.Parallel()

	captured := make(chan clientsRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/control/clients/search":
			assert.Equal(t, http.MethodPost, r.Method)

			body, err := io.ReadAll(r.Body)
			captured <- clientsRequestCapture{body: string(body), err: err}
		case "/control/clients/find":
			assert.Equal(t, http.MethodGet, r.Method)
			assert.Equal(t, "ip0=192.0.2.1&ip1=cli-42", r.URL.RawQuery)
		default:
			http.NotFound(w, r)

			return
		}

		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `[{"192.0.2.1":{"name":"desk","ids":["192.0.2.1"],"filtering_enabled":true}}]`)
	}))
	client := newClientsClient(t, server, 1024)

	search, err := client.ClientsSearch(t.Context(), ClientsSearchRequest{
		Clients: []ClientsSearchRequestItem{{ID: clientsTestClientID}, {ID: "cli-42"}},
	})
	require.NoError(t, err)

	request := <-captured
	require.NoError(t, request.err)
	assert.JSONEq(t, `{"clients":[{"id":"192.0.2.1"},{"id":"cli-42"}]}`, request.body)
	require.Len(t, search, 1)
	assert.Equal(t, clientsTestName, search[0][clientsTestClientID].Name)

	found, err := client.ClientsFind(t.Context(), clientsTestClientID, "cli-42")
	require.NoError(t, err)
	require.Len(t, found, 1)
	assert.Equal(t, clientsTestName, found[0][clientsTestClientID].Name)
}

// TestAccessList verifies access-list response decoding.
func TestAccessList(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/access/list", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"allowed_clients":["192.0.2.1"],"disallowed_clients":[],"blocked_hosts":["ads.example"]}`)
	}))
	client := newClientsClient(t, server, 1024)

	access, err := client.AccessList(t.Context())

	require.NoError(t, err)
	assert.Equal(t, []string{clientsTestClientID}, access.AllowedClients)
	assert.Empty(t, access.DisallowedClients)
	assert.Equal(t, []string{clientsTestBlockedHost}, access.BlockedHosts)
}

// TestClientsValidatesRequiredFieldsBeforeRequest verifies validation precedes transport.
func TestClientsValidatesRequiredFieldsBeforeRequest(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("unexpected request")
	}))
	client := newClientsClient(t, server, 1024)
	var (
		emptyClientConfig ClientConfig
		emptyClientDelete ClientDelete
	)

	assertConfigError(t, client.ClientsAdd(t.Context(), emptyClientConfig))
	assertConfigError(t, client.ClientsDelete(t.Context(), emptyClientDelete))
	assertConfigError(t, client.ClientsUpdate(t.Context(), ClientUpdate{
		Name: clientsTestName,
		Data: nil,
	}))

	_, err := client.ClientsSearch(t.Context(), ClientsSearchRequest{
		Clients: []ClientsSearchRequestItem{{ID: ""}},
	})
	assertConfigError(t, err)
	assertConfigError(t, client.AccessSet(t.Context(), AccessList{
		AllowedClients:    []string{"one", "one"},
		DisallowedClients: nil,
		BlockedHosts:      nil,
	}))
}

// TestClientsRejectsMalformedJSONAndNonSuccess verifies response error translation.
func TestClientsRejectsMalformedJSONAndNonSuccess(t *testing.T) {
	t.Parallel()

	t.Run("malformed", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			writeBody(w, `{"clients":`)
		}))
		client := newClientsClient(t, server, 1024)

		_, err := client.ClientsStatus(t.Context())

		assert.Error(t, requireClientError(t, err, ErrorKindJSON))
	})

	t.Run("top-level null", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			writeBody(w, `null`)
		}))
		client := newClientsClient(t, server, 1024)

		_, statusErr := client.ClientsStatus(t.Context())
		require.Error(t, requireClientError(t, statusErr, ErrorKindJSON))

		_, searchErr := client.ClientsSearch(t.Context(), ClientsSearchRequest{
			Clients: []ClientsSearchRequestItem{{ID: clientsTestClientID}},
		})
		require.Error(t, requireClientError(t, searchErr, ErrorKindJSON))

		_, findErr := client.ClientsFind(t.Context(), clientsTestClientID)
		require.Error(t, requireClientError(t, findErr, ErrorKindJSON))

		_, accessErr := client.AccessList(t.Context())
		assert.Error(t, requireClientError(t, accessErr, ErrorKindJSON))
	})

	t.Run("non-success", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			writeBody(w, "invalid client")
		}))
		client := newClientsClient(t, server, 1024)

		err := client.ClientsDelete(t.Context(), ClientDelete{Name: "desk"})

		clientErr := requireClientError(t, err, ErrorKindStatus)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.Equal(t, http.StatusBadRequest, clientErr.StatusCode)
		assert.Equal(t, "invalid client", string(clientErr.Body))
	})
}

// TestClientsEnforcesResponseLimitAndCancellation verifies bounded reads and cancellation.
func TestClientsEnforcesResponseLimitAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("limit", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			writeBody(w, `{"clients":[]}`)
		}))
		client := newClientsClient(t, server, 3)

		_, err := client.ClientsStatus(t.Context())

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, int64(3), clientErr.Limit)
	})

	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		client := newClientsClient(t, server, 1024)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, err := client.ClientsStatus(ctx)

		clientErr := requireClientError(t, err, ErrorKindRequest)
		assert.Equal(t, http.MethodGet, clientErr.Method)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// newClientsAddConfig returns the complete add-client request fixture.
//
// Returns:
//   - The configured client fixture.
func newClientsAddConfig() ClientConfig {
	return ClientConfig{
		Name:                     clientsTestName,
		IDs:                      []string{clientsTestClientID},
		UseGlobalSettings:        false,
		FilteringEnabled:         true,
		ParentalEnabled:          false,
		SafebrowsingEnabled:      false,
		SafesearchEnabled:        false,
		SafeSearch:               nil,
		UseGlobalBlockedServices: false,
		BlockedServicesSchedule:  nil,
		BlockedServices:          nil,
		Upstreams:                nil,
		Tags:                     nil,
		IgnoreQuerylog:           false,
		IgnoreStatistics:         false,
		UpstreamsCacheEnabled:    false,
		UpstreamsCacheSize:       0,
	}
}

// newClientsUpdateData returns a fully specified presence-sensitive update fixture.
//
// Parameters:
//   - filteringEnabled: The filtering setting pointer to include.
//   - useGlobalSettings: The global-settings pointer to include.
//
// Returns:
//   - The client update fixture.
func newClientsUpdateData(filteringEnabled, useGlobalSettings *bool) *ClientUpdateData {
	return &ClientUpdateData{
		Name:                     nil,
		IDs:                      nil,
		UseGlobalSettings:        useGlobalSettings,
		FilteringEnabled:         filteringEnabled,
		ParentalEnabled:          nil,
		SafebrowsingEnabled:      nil,
		SafesearchEnabled:        nil,
		SafeSearch:               nil,
		UseGlobalBlockedServices: nil,
		BlockedServicesSchedule:  nil,
		BlockedServices:          nil,
		Upstreams:                nil,
		Tags:                     nil,
		IgnoreQuerylog:           nil,
		IgnoreStatistics:         nil,
		UpstreamsCacheEnabled:    nil,
		UpstreamsCacheSize:       nil,
	}
}

// newClientsClient creates a client bound to a test server.
//
// Parameters:
//   - server: The HTTP test server.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - The configured AdGuard client.
func newClientsClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL,
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithMaxResponseBodySize(limit),
		WithRequestTimeout(time.Second),
	)
	require.NoError(t, err)

	return client
}

// assertConfigError asserts that err is a client configuration error.
//
// Parameters:
//   - err: The error to inspect.
func assertConfigError(t *testing.T, err error) {
	t.Helper()

	var clientErr *Error

	require.ErrorAs(t, err, &clientErr)
	assert.Equal(t, ErrorKindConfig, clientErr.Kind)
}
