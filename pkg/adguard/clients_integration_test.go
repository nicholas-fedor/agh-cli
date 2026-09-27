// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// clientsIntegrationRequestCapture contains one captured workflow request.
type clientsIntegrationRequestCapture struct {
	accept      string
	body        []byte
	closeErr    error
	contentType string
	hasAuth     bool
	method      string
	path        string
	query       string
	readErr     error
	userAgent   string
	username    string
	password    string
}

// clientsIntegrationRequestAssertion asserts one captured workflow request.
type clientsIntegrationRequestAssertion func(wantMethod, wantPath, wantBody string)

const (
	// The access-list response returned by the test server.
	clientsIntegrationAccessResponse = `{
		"allowed_clients":["192.0.2.10"],
		"disallowed_clients":[],
		"blocked_hosts":["ads.example"]
	}`
	// The fixed loopback base URL routed by the test transport.
	clientsIntegrationBaseURL = "http://127.0.0.1"
	// The blocked host shared by the access-list fixtures.
	clientsIntegrationBlockedHost = "ads.example"
	// The configured desk client identifier.
	clientsIntegrationDeskID = "192.0.2.10"
	// The configured desk client name.
	clientsIntegrationDeskName = "desk"
	// The laptop client's IP address.
	clientsIntegrationLaptopIP = "192.0.2.20"
	// The laptop client's MAC address.
	clientsIntegrationLaptopMAC = "08:00:2b:01:02:03"
	// The configured laptop client name.
	clientsIntegrationLaptopName = "laptop"
	// The expected HTTP Basic password.
	clientsIntegrationPassword = "clients-integration-password"
	// The structured error response media type.
	clientsIntegrationProblemMediaType = "application/problem+json; charset=utf-8"
	// The client-search response returned by the test server.
	clientsIntegrationSearchResponse = `[
		{
			"192.0.2.10":{
				"name":"desk",
				"ids":["192.0.2.10"],
				"filtering_enabled":false,
				"safe_search":{},
				"upstreams":[],
				"ignore_statistics":false
			}
		},
		{
			"08:00:2b:01:02:03":{
				"name":"laptop",
				"ids":["192.0.2.20","08:00:2b:01:02:03"],
				"use_global_settings":true,
				"filtering_enabled":true,
				"safebrowsing_enabled":true,
				"safesearch_enabled":true,
				"use_global_blocked_services":true,
				"blocked_services":["youtube"],
				"upstreams":["https://dns.example/dns-query"],
				"ignore_querylog":true,
				"ignore_statistics":false
			}
		}
	]`
	// The structured delete-conflict response body.
	clientsIntegrationStatusBody = `{"message":"client is already absent","code":"client_not_found"}`
	// The client-status response returned by the test server.
	clientsIntegrationStatusResponse = `{
		"clients":[{
			"name":"desk",
			"ids":["192.0.2.10"],
			"filtering_enabled":true,
			"tags":["trusted"],
			"upstreams_cache_size":4096
		}],
		"auto_clients":[{
			"ip":"192.0.2.20",
			"name":"phone",
			"source":"arp",
			"whois_info":{"country":"US"}
		}],
		"supported_tags":["trusted","child"]
	}`
	// The expected client User-Agent.
	clientsIntegrationUserAgent = "clients-integration-client/1.0"
	// The expected HTTP Basic username.
	clientsIntegrationUsername = "clients-integration-user"
)

// TestClientsHTTPWorkflow verifies a complete client and access-list HTTP workflow.
func TestClientsHTTPWorkflow(t *testing.T) {
	t.Parallel()

	server, captured := newClientsIntegrationServer(t)
	client := newClientsIntegrationClient(t, server)
	assertRequest := newClientsIntegrationRequestAsserter(t, captured)

	exerciseClientsIntegrationStatusAndAdd(t, client, assertRequest)
	exerciseClientsIntegrationUpdateAndSearch(t, client, assertRequest)
	exerciseClientsIntegrationAccess(t, client, assertRequest)
	exerciseClientsIntegrationDelete(t, client, assertRequest)
}

// newClientsIntegrationServer creates the stateful HTTP test server.
//
// Returns:
//   - server: The running HTTP test server.
//   - captured: The receive-only request capture channel.
func newClientsIntegrationServer(
	t *testing.T,
) (*httptest.Server, <-chan clientsIntegrationRequestCapture) {
	t.Helper()

	requestChannel := make(chan clientsIntegrationRequestCapture, 8)
	var deleted atomic.Bool

	jsonHandler := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
			writeClientsIntegrationResponse(w, body)
		}
	}
	emptyHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handlers := map[string]http.Handler{
		"GET /control/clients":         jsonHandler(clientsIntegrationStatusResponse),
		"POST /control/clients/add":    emptyHandler,
		"POST /control/clients/update": emptyHandler,
		"POST /control/clients/search": jsonHandler(clientsIntegrationSearchResponse),
		"GET /control/access/list":     jsonHandler(clientsIntegrationAccessResponse),
		"POST /control/access/set":     emptyHandler,
		"POST /control/clients/delete": http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if deleted.Swap(true) {
				w.Header().Set("Content-Type", clientsIntegrationProblemMediaType)
				w.WriteHeader(http.StatusConflict)
				writeClientsIntegrationResponse(w, clientsIntegrationStatusBody)

				return
			}

			w.WriteHeader(http.StatusOK)
		}),
	}

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestChannel <- captureClientsIntegrationRequest(r)

		requestHandler, found := handlers[r.Method+" "+r.URL.Path]
		if !found {
			http.NotFound(w, r)

			return
		}

		requestHandler.ServeHTTP(w, r)
	}))

	return server, requestChannel
}

// newClientsIntegrationClient creates the concrete client used by the workflow.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//
// Returns:
//   - client: The configured AdGuard client.
func newClientsIntegrationClient(t *testing.T, server *httptest.Server) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		clientsIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(clientsIntegrationUsername, clientsIntegrationPassword),
		adguard.WithUserAgent(clientsIntegrationUserAgent),
	)
	require.NoError(t, err)

	return client
}

// newClientsIntegrationRequestAsserter creates the captured-request assertion function.
//
// Parameters:
//   - captured: The receive-only request capture channel.
//
// Returns:
//   - assertRequest: The function that asserts one captured HTTP request.
func newClientsIntegrationRequestAsserter(
	t *testing.T,
	captured <-chan clientsIntegrationRequestCapture,
) clientsIntegrationRequestAssertion {
	t.Helper()

	// The media type every client request and response must carry.
	expectedMediaType := blockedServicesIntegrationJSONContentType

	return func(wantMethod, wantPath, wantBody string) {
		t.Helper()

		request := <-captured
		require.NoError(t, request.readErr)
		require.NoError(t, request.closeErr)
		assert.Equal(t, wantMethod, request.method)
		assert.Equal(t, wantPath, request.path)
		assert.Empty(t, request.query)
		assert.Equal(t, expectedMediaType, request.accept)
		assert.Equal(t, clientsIntegrationUserAgent, request.userAgent)
		assert.True(t, request.hasAuth)
		assert.Equal(t, clientsIntegrationUsername, request.username)
		assert.Equal(t, clientsIntegrationPassword, request.password)

		if wantBody == "" {
			assert.Empty(t, request.body)
			assert.Empty(t, request.contentType)

			return
		}

		assert.Equal(t, expectedMediaType, request.contentType)
		assert.JSONEq(t, wantBody, string(request.body))
	}
}

// exerciseClientsIntegrationStatusAndAdd verifies client status and add requests.
//
// Parameters:
//   - client: The AdGuard client under test.
//   - assertRequest: The captured-request assertion function.
func exerciseClientsIntegrationStatusAndAdd(
	t *testing.T,
	client *adguard.Client,
	assertRequest clientsIntegrationRequestAssertion,
) {
	t.Helper()

	status, err := client.ClientsStatus(t.Context())
	require.NoError(t, err)
	assertRequest(http.MethodGet, "/control/clients", "")
	require.Len(t, status.Clients, 1)
	assert.Equal(t, clientsIntegrationDeskName, status.Clients[0].Name)
	assert.Equal(t, []string{clientsIntegrationDeskID}, status.Clients[0].IDs)
	assert.True(t, status.Clients[0].FilteringEnabled)
	require.Len(t, status.AutoClients, 1)
	assert.Equal(t, "phone", status.AutoClients[0].Name)
	assert.Equal(t, []string{"trusted", "child"}, status.SupportedTags)

	err = client.ClientsAdd(t.Context(), adguard.ClientConfig{
		Name:                     clientsIntegrationLaptopName,
		IDs:                      []string{clientsIntegrationLaptopIP, clientsIntegrationLaptopMAC},
		UseGlobalSettings:        true,
		FilteringEnabled:         true,
		SafebrowsingEnabled:      true,
		SafesearchEnabled:        true,
		UseGlobalBlockedServices: true,
		BlockedServices:          []string{safetyIntegrationYouTubeKey},
		Upstreams:                []string{"https://dns.example/dns-query"},
		Tags:                     []string{"trusted"},
		IgnoreQuerylog:           true,
		UpstreamsCacheEnabled:    true,
		UpstreamsCacheSize:       4096,
	})
	require.NoError(t, err)
	assertRequest(
		http.MethodPost,
		"/control/clients/add",
		`{
			"name":"laptop",
			"ids":["192.0.2.20","08:00:2b:01:02:03"],
			"use_global_settings":true,
			"filtering_enabled":true,
			"safebrowsing_enabled":true,
			"safesearch_enabled":true,
			"use_global_blocked_services":true,
			"blocked_services":["youtube"],
			"upstreams":["https://dns.example/dns-query"],
			"tags":["trusted"],
			"ignore_querylog":true,
			"upstreams_cache_enabled":true,
			"upstreams_cache_size":4096
		}`,
	)
}

// exerciseClientsIntegrationUpdateAndSearch verifies update presence and client search.
//
// Parameters:
//   - client: The AdGuard client under test.
//   - assertRequest: The captured-request assertion function.
func exerciseClientsIntegrationUpdateAndSearch(
	t *testing.T,
	client *adguard.Client,
	assertRequest clientsIntegrationRequestAssertion,
) {
	t.Helper()

	err := client.ClientsUpdate(t.Context(), adguard.ClientUpdate{
		Name: clientsIntegrationDeskName,
		Data: &adguard.ClientUpdateData{
			IDs:                new([]string{}),
			FilteringEnabled:   new(false),
			SafeSearch:         &adguard.SafeSearchConfig{},
			Upstreams:          new([]string{}),
			Tags:               new([]string{}),
			IgnoreStatistics:   new(false),
			UpstreamsCacheSize: new(int64(0)),
		},
	})
	require.NoError(t, err)
	assertRequest(
		http.MethodPost,
		"/control/clients/update",
		`{
			"name":"desk",
			"data":{
				"ids":[],
				"filtering_enabled":false,
				"safe_search":{},
				"upstreams":[],
				"tags":[],
				"ignore_statistics":false,
				"upstreams_cache_size":0
			}
		}`,
	)

	found, err := client.ClientsSearch(t.Context(), adguard.ClientsSearchRequest{
		Clients: []adguard.ClientsSearchRequestItem{
			{ID: clientsIntegrationDeskID},
			{ID: clientsIntegrationLaptopMAC},
		},
	})
	require.NoError(t, err)
	assertRequest(
		http.MethodPost,
		"/control/clients/search",
		`{"clients":[{"id":"192.0.2.10"},{"id":"08:00:2b:01:02:03"}]}`,
	)
	require.Len(t, found, 2)
	assert.Equal(t, clientsIntegrationDeskName, found[0][clientsIntegrationDeskID].Name)
	assert.False(t, found[0][clientsIntegrationDeskID].FilteringEnabled)
	assert.Empty(t, found[0][clientsIntegrationDeskID].Upstreams)
	require.NotNil(t, found[0][clientsIntegrationDeskID].SafeSearch)
	assert.Empty(t, *found[0][clientsIntegrationDeskID].SafeSearch)
	assert.Equal(t, clientsIntegrationLaptopName, found[1][clientsIntegrationLaptopMAC].Name)
}

// exerciseClientsIntegrationAccess verifies access-list reads and replacement.
//
// Parameters:
//   - client: The AdGuard client under test.
//   - assertRequest: The captured-request assertion function.
func exerciseClientsIntegrationAccess(
	t *testing.T,
	client *adguard.Client,
	assertRequest clientsIntegrationRequestAssertion,
) {
	t.Helper()

	access, err := client.AccessList(t.Context())
	require.NoError(t, err)
	assertRequest(http.MethodGet, "/control/access/list", "")
	assert.Equal(t, []string{clientsIntegrationDeskID}, access.AllowedClients)
	assert.NotNil(t, access.DisallowedClients)
	assert.Empty(t, access.DisallowedClients)
	assert.Equal(t, []string{clientsIntegrationBlockedHost}, access.BlockedHosts)

	err = client.AccessSet(t.Context(), adguard.AccessList{
		AllowedClients:    []string{clientsIntegrationDeskID},
		DisallowedClients: []string{clientsIntegrationLaptopIP},
		BlockedHosts:      []string{clientsIntegrationBlockedHost, "telemetry.example"},
	})
	require.NoError(t, err)
	assertRequest(
		http.MethodPost,
		"/control/access/set",
		`{
			"allowed_clients":["192.0.2.10"],
			"disallowed_clients":["192.0.2.20"],
			"blocked_hosts":["ads.example","telemetry.example"]
		}`,
	)
}

// exerciseClientsIntegrationDelete verifies successful deletion and a structured conflict.
//
// Parameters:
//   - client: The AdGuard client under test.
//   - assertRequest: The captured-request assertion function.
func exerciseClientsIntegrationDelete(
	t *testing.T,
	client *adguard.Client,
	assertRequest clientsIntegrationRequestAssertion,
) {
	t.Helper()

	deleteRequest := adguard.ClientDelete{Name: clientsIntegrationDeskName}
	err := client.ClientsDelete(t.Context(), deleteRequest)
	require.NoError(t, err)

	assertRequest(http.MethodPost, "/control/clients/delete", `{"name":"desk"}`)

	err = client.ClientsDelete(t.Context(), deleteRequest)

	assertRequest(http.MethodPost, "/control/clients/delete", `{"name":"desk"}`)
	require.Error(t, err)

	clientErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	assert.Equal(t, adguard.ErrorKindStatus, clientErr.Kind)
	assert.Equal(t, "clients_delete", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusConflict, clientErr.StatusCode)
	assert.Equal(t, "409 Conflict", clientErr.Status)
	assert.Equal(t, clientsIntegrationProblemMediaType, clientErr.ContentType)
	assert.JSONEq(t, clientsIntegrationStatusBody, string(clientErr.Body))
	assert.NoError(t, clientErr.Err)
}

// captureClientsIntegrationRequest reads and records one HTTP request.
//
// Parameters:
//   - request: The HTTP request captured by the test server.
//
// Returns:
//   - capture: The captured request metadata and body errors.
func captureClientsIntegrationRequest(request *http.Request) clientsIntegrationRequestCapture {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	username, password, hasAuth := request.BasicAuth()

	return clientsIntegrationRequestCapture{
		accept:      request.Header.Get("Accept"),
		body:        body,
		closeErr:    closeErr,
		contentType: request.Header.Get("Content-Type"),
		hasAuth:     hasAuth,
		method:      request.Method,
		path:        request.URL.Path,
		query:       request.URL.RawQuery,
		readErr:     readErr,
		userAgent:   request.Header.Get("User-Agent"),
		username:    username,
		password:    password,
	}
}

// writeClientsIntegrationResponse writes a response body while tolerating client disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeClientsIntegrationResponse(w http.ResponseWriter, body string) {
	_, err := io.WriteString(w, body)
	if err != nil {
		return
	}
}
