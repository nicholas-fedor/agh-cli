// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dhcpRequestCapture carries request metadata and body-read errors across the
// handler boundary.
type dhcpRequestCapture struct {
	// body contains the bytes read from the request body.
	body []byte
	// contentLength is the request body's declared content length.
	contentLength int64
	// contentType is the request body's media type.
	contentType string
	// err is the error encountered while reading the request body.
	err error
	// method is the HTTP request method.
	method string
	// path is the request URL path without its query.
	path string
}

// dhcpConfigRequestCase describes one DHCP configuration request contract.
type dhcpConfigRequestCase struct {
	// name identifies the subtest.
	name string
	// config is the request value, where nil omits the body.
	config *DHCPConfig
	// expectBody reports whether the request must contain a JSON body.
	expectBody bool
	// expectedBody is the decoded JSON body expected by the test.
	expectedBody map[string]any
}

// dhcpStaticLeaseMutationCase describes one DHCP static-lease mutation
// contract.
type dhcpStaticLeaseMutationCase struct {
	// name identifies the subtest.
	name string
	// path is the expected control endpoint path.
	path string
	// expectedBody is the exact expected JSON request body.
	expectedBody string
	// call invokes one static-lease mutation.
	call func(context.Context, *Client) error
}

// dhcpFindActiveRequestCase describes one DHCP active-search request contract.
type dhcpFindActiveRequestCase struct {
	// name identifies the subtest.
	name string
	// request is the request value, where nil omits the body.
	request *DHCPFindRequest
	// expectBody reports whether the request must contain a JSON body.
	expectBody bool
	// expectedBody is the decoded JSON body expected by the test.
	expectedBody map[string]any
}

// dhcpInvalidJSONCase describes one invalid DHCP response contract.
type dhcpInvalidJSONCase struct {
	// name identifies the subtest.
	name string
	// body is the response body returned by the test server.
	body string
	// contentType is the response media type returned by the test server.
	contentType string
	// method is the HTTP method expected on the structured error.
	method string
	// call invokes the DHCP operation under test.
	call func(context.Context, *Client) error
	// kind is the expected structured error kind.
	kind ErrorKind
}

// dhcpStatusErrorCase describes one non-success DHCP response contract.
type dhcpStatusErrorCase struct {
	// name identifies the subtest.
	name string
	// method is the HTTP method expected on the structured error.
	method string
	// statusCode is the HTTP status returned by the test server.
	statusCode int
	// expectedBody is the message included in the response body.
	expectedBody string
	// call invokes the DHCP operation under test.
	call func(context.Context, *Client) error
}

const (
	// DhcpTestUsername is the Basic Auth username used by DHCP tests.
	dhcpTestUsername = "dhcp-user"
	// DhcpTestPassword is the Basic Auth password used by DHCP tests.
	dhcpTestPassword = "dhcp-password"
	// DhcpTestUserAgent is the User-Agent used by DHCP tests.
	dhcpTestUserAgent = "adguard-dhcp-test/1.0"
	// DhcpTestInterfaceName is the interface name used by DHCP fixtures.
	dhcpTestInterfaceName = "eth0"
	// DhcpTestPrinterHostname is the static-lease hostname used by DHCP fixtures.
	dhcpTestPrinterHostname = "printer"
	// DhcpTestPrinterIP is the static-lease address used by DHCP fixtures.
	dhcpTestPrinterIP = "192.0.2.20"
	// DhcpTestUpdatedHostname is the replacement static-lease hostname.
	dhcpTestUpdatedHostname = "printer-new"
	// DhcpTestUpdatedIP is the replacement static-lease address.
	dhcpTestUpdatedIP = "192.0.2.21"
	// DhcpTestPrinterMAC is the static-lease hardware address used by DHCP fixtures.
	dhcpTestPrinterMAC = "00:11:22:33:44:66"
	// DhcpNotImplementedBody is the message used for unsupported DHCP responses.
	dhcpNotImplementedBody = "not implemented"
	// DhcpFindActiveResponseJSON is the successful active-search response fixture.
	dhcpFindActiveResponseJSON = `{
		"v4":{
			"other_server":{"found":"no","error":null},
			"static_ip":{"static":"no","ip":"192.0.2.10"}
		},
		"v6":{"other_server":{"found":"error","error":"timeout"}}
	}`
)

// TestClientDHCPStatus verifies DHCP status decoding and its response contract.
func TestClientDHCPStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, dhcpTestUsername, username)
		assert.Equal(t, dhcpTestPassword, password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/dhcp/status", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, dhcpJSONMediaTypeValue(), r.Header.Get("Accept"))
		assert.Equal(t, dhcpTestUserAgent, r.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeBody(w, `{
			"config":{"ignored":true},
			"enabled":false,
			"interface_name":null,
			"v4":{
				"gateway_ip":"192.0.2.1",
				"subnet_mask":"255.255.255.0",
				"range_start":"192.0.2.10",
				"range_end":"192.0.2.100",
				"lease_duration":0
			},
			"v6":{"range_start":null,"lease_duration":0},
			"leases":[{
				"expires":"2026-09-25T01:00:00Z",
				"hostname":"laptop",
				"ip":"192.0.2.10",
				"mac":"00:11:22:33:44:55"
			}],
			"static_leases":[]
		}`)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	status, err := client.DHCPStatus(t.Context())

	require.NoError(t, err)
	require.NotNil(t, status.Enabled)
	assert.False(t, *status.Enabled)
	assert.Nil(t, status.InterfaceName)
	require.NotNil(t, status.V4)
	assert.Equal(t, "192.0.2.1", *status.V4.GatewayIP)
	assert.Equal(t, "255.255.255.0", *status.V4.SubnetMask)
	assert.Equal(t, "192.0.2.10", *status.V4.RangeStart)
	assert.Equal(t, "192.0.2.100", *status.V4.RangeEnd)
	require.NotNil(t, status.V4.LeaseDuration)
	assert.Zero(t, *status.V4.LeaseDuration)
	require.NotNil(t, status.V6)
	assert.Nil(t, status.V6.RangeStart)
	require.NotNil(t, status.V6.LeaseDuration)
	assert.Zero(t, *status.V6.LeaseDuration)
	require.Len(t, status.Leases, 1)
	assert.Equal(t, DHCPLease{
		Expires:  "2026-09-25T01:00:00Z",
		Hostname: "laptop",
		IP:       "192.0.2.10",
		MAC:      "00:11:22:33:44:55",
	}, status.Leases[0])
	require.NotNil(t, status.StaticLeases)
	assert.Empty(t, *status.StaticLeases)
}

// TestClientDHCPInterfaces verifies DHCP interface decoding and its response
// contract.
func TestClientDHCPInterfaces(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/dhcp/interfaces", r.URL.Path)
		w.Header().Set("Content-Type", testResponseMediaType)
		writeBody(w, `{
			"eth0":{
				"flags":"up|broadcast|multicast",
				"gateway_ip":"192.0.2.1",
				"hardware_address":"52:54:00:12:34:56",
				"ipv4_addresses":["192.0.2.10/24"],
				"ipv6_addresses":["2001:db8::10/64"],
				"name":"eth0"
			}
		}`)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	interfaces, err := client.DHCPInterfaces(t.Context())

	require.NoError(t, err)
	assert.Equal(t, map[string]DHCPInterface{
		dhcpTestInterfaceName: {
			Flags:           "up|broadcast|multicast",
			GatewayIP:       clientsTestClientID,
			HardwareAddress: "52:54:00:12:34:56",
			IPv4Addresses:   []string{"192.0.2.10/24"},
			IPv6Addresses:   []string{"2001:db8::10/64"},
			Name:            dhcpTestInterfaceName,
		},
	}, interfaces)
}

// TestClientDHCPConfigRequestPresence verifies omitted, empty, and explicit
// DHCP config bodies.
func TestClientDHCPConfigRequestPresence(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpConfigRequestCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testDHCPConfigRequest(t, test)
		})
	}
}

// dhcpConfigRequestCases returns DHCP config request-presence cases.
//
// Returns:
//   - The omitted, empty, and explicit-zero configuration cases.
func dhcpConfigRequestCases() []dhcpConfigRequestCase {
	return []dhcpConfigRequestCase{
		{
			name:         "omitted body",
			config:       nil,
			expectBody:   false,
			expectedBody: nil,
		},
		{
			name:         "empty object",
			config:       newDHCPEmptyConfig(),
			expectBody:   true,
			expectedBody: map[string]any{},
		},
		{
			name:       "explicit zero values",
			config:     newDHCPExplicitZeroConfig(),
			expectBody: true,
			expectedBody: map[string]any{
				safetyEnabledKey: false,
				"interface_name": dhcpTestInterfaceName,
				"v4": map[string]any{
					"gateway_ip":     "",
					"lease_duration": float64(0),
				},
				"v6": map[string]any{},
			},
		},
	}
}

// testDHCPConfigRequest verifies one DHCP config request contract.
//
// Parameters:
//   - test: The request-presence case to exercise.
func testDHCPConfigRequest(t *testing.T, test dhcpConfigRequestCase) {
	t.Helper()

	captured := make(chan dhcpRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		captured <- newDHCPRequestCapture(r, body, err)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	err := client.DHCPConfig(t.Context(), test.config)
	request := <-captured

	require.NoError(t, request.err)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, "/api/control/dhcp/set_config", request.path)

	if !test.expectBody {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.contentType)
		assert.Empty(t, request.body)

		return
	}

	assert.Equal(t, dhcpJSONMediaTypeValue(), request.contentType)

	var actual map[string]any

	require.NoError(t, json.Unmarshal(request.body, &actual))
	assert.Equal(t, test.expectedBody, actual)
}

// TestClientDHCPStaticLeaseMutations verifies add, remove, and update lease
// requests.
func TestClientDHCPStaticLeaseMutations(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpStaticLeaseMutationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testDHCPStaticLeaseMutation(t, test)
		})
	}
}

// dhcpStaticLeaseMutationCases returns static-lease mutation contracts.
//
// Returns:
//   - The add, remove, and update request cases.
func dhcpStaticLeaseMutationCases() []dhcpStaticLeaseMutationCase {
	return []dhcpStaticLeaseMutationCase{
		{
			name:         clientsAddTestName,
			path:         "/api/control/dhcp/add_static_lease",
			expectedBody: `{"hostname":"printer","ip":"192.0.2.20","mac":"00:11:22:33:44:66"}`,
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPAddStaticLease(ctx, newDHCPStaticLease())
			},
		},
		{
			name:         "remove",
			path:         "/api/control/dhcp/remove_static_lease",
			expectedBody: `{"hostname":"printer","ip":"192.0.2.20","mac":"00:11:22:33:44:66"}`,
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPRemoveStaticLease(ctx, newDHCPStaticLease())
			},
		},
		{
			name:         clientsUpdateTestName,
			path:         "/api/control/dhcp/update_static_lease",
			expectedBody: `{"hostname":"printer-new","ip":"192.0.2.21","mac":"00:11:22:33:44:66"}`,
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPUpdateStaticLease(ctx, newDHCPUpdatedStaticLease())
			},
		},
	}
}

// testDHCPStaticLeaseMutation verifies one static-lease mutation contract.
//
// Parameters:
//   - test: The mutation case to exercise.
func testDHCPStaticLeaseMutation(t *testing.T, test dhcpStaticLeaseMutationCase) {
	t.Helper()

	captured := make(chan dhcpRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		captured <- newDHCPRequestCapture(r, body, err)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.WriteHeader(http.StatusOK)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	err := test.call(t.Context(), client)
	request := <-captured

	require.NoError(t, request.err)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, test.path, request.path)
	assert.Equal(t, dhcpJSONMediaTypeValue(), request.contentType)
	assert.Equal(t, test.expectedBody, string(request.body))
}

// TestClientDHCPFindActiveRequestPresence verifies DHCP active-search request
// presence and decoding.
func TestClientDHCPFindActiveRequestPresence(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpFindActiveRequestCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testDHCPFindActiveRequest(t, test)
		})
	}
}

// dhcpFindActiveRequestCases returns active-search request-presence cases.
//
// Returns:
//   - The omitted, empty, and interface-present cases.
func dhcpFindActiveRequestCases() []dhcpFindActiveRequestCase {
	return []dhcpFindActiveRequestCase{
		{
			name:         "omitted body",
			request:      nil,
			expectBody:   false,
			expectedBody: nil,
		},
		{
			name:         "empty object",
			request:      newDHCPEmptyFindRequest(),
			expectBody:   true,
			expectedBody: map[string]any{},
		},
		{
			name: "interface present",
			request: &DHCPFindRequest{
				Interface: new(dhcpTestInterfaceName),
			},
			expectBody:   true,
			expectedBody: map[string]any{"interface": dhcpTestInterfaceName},
		},
	}
}

// testDHCPFindActiveRequest verifies one active-search request and response
// contract.
//
// Parameters:
//   - test: The active-search case to exercise.
func testDHCPFindActiveRequest(t *testing.T, test dhcpFindActiveRequestCase) {
	t.Helper()

	captured := make(chan dhcpRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		captured <- newDHCPRequestCapture(r, body, err)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", testResponseMediaType)
		writeBody(w, dhcpFindActiveResponseJSON)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	result, err := client.DHCPFindActive(t.Context(), test.request)
	request := <-captured

	require.NoError(t, request.err)
	require.NoError(t, err)
	assert.Equal(t, http.MethodPost, request.method)
	assert.Equal(t, "/api/control/dhcp/find_active_dhcp", request.path)

	if test.expectBody {
		assert.Equal(t, dhcpJSONMediaTypeValue(), request.contentType)

		var actual map[string]any

		require.NoError(t, json.Unmarshal(request.body, &actual))
		assert.Equal(t, test.expectedBody, actual)
	} else {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.contentType)
		assert.Empty(t, request.body)
	}

	require.NotNil(t, result)
	assertDHCPFindActiveResult(t, result)
}

// assertDHCPFindActiveResult verifies the typed active-search response.
//
// Parameters:
//   - result: The response to inspect.
func assertDHCPFindActiveResult(t *testing.T, result *DHCPFindResult) {
	t.Helper()

	require.NotNil(t, result.V4)
	require.NotNil(t, result.V4.OtherServer)
	require.NotNil(t, result.V4.OtherServer.Found)
	assert.Equal(t, DHCPSearchStatusNo, *result.V4.OtherServer.Found)
	assert.Nil(t, result.V4.OtherServer.Error)
	require.NotNil(t, result.V4.StaticIP)
	require.NotNil(t, result.V4.StaticIP.Status)
	assert.Equal(t, DHCPSearchStatusNo, *result.V4.StaticIP.Status)
	assert.Equal(t, "192.0.2.10", *result.V4.StaticIP.IP)
	require.NotNil(t, result.V6)
	require.NotNil(t, result.V6.OtherServer)
	require.NotNil(t, result.V6.OtherServer.Found)
	assert.Equal(t, DHCPSearchStatusError, *result.V6.OtherServer.Found)
	require.NotNil(t, result.V6.OtherServer.Error)
	assert.Equal(t, "timeout", *result.V6.OtherServer.Error)
}

// TestClientDHCPResets verifies DHCP configuration and lease reset requests.
func TestClientDHCPResets(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path string
		call func(context.Context, *Client) error
	}{
		"configuration": {
			path: "/api/control/dhcp/reset",
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPReset(ctx)
			},
		},
		"leases": {
			path: "/api/control/dhcp/reset_leases",
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPResetLeases(ctx)
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, test.path, r.URL.Path)
				assert.Zero(t, r.ContentLength)
				assert.Empty(t, r.Header.Get("Content-Type"))
				w.WriteHeader(http.StatusOK)
			}))
			client := newDHCPTLSTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			require.NoError(t, err)
		})
	}
}

// TestClientDHCPRejectsInvalidJSON verifies malformed responses and media-type
// failures.
func TestClientDHCPRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpInvalidJSONCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testDHCPInvalidJSONCase(t, test)
		})
	}
}

// dhcpInvalidJSONCases returns all invalid DHCP response cases.
//
// Returns:
//   - The malformed, null, missing-field, enum, and media-type cases.
func dhcpInvalidJSONCases() []dhcpInvalidJSONCase {
	return append(dhcpInvalidJSONResponseCases(), dhcpInvalidJSONContractCases()...)
}

// dhcpInvalidJSONResponseCases returns malformed status and missing-field
// cases.
//
// Returns:
//   - The status response validation cases.
func dhcpInvalidJSONResponseCases() []dhcpInvalidJSONCase {
	return []dhcpInvalidJSONCase{
		{
			name:        "malformed status",
			body:        `{"leases":`,
			contentType: testResponseMediaType,
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
			kind: ErrorKindJSON,
		},
		{
			name:        "null status",
			body:        testNullJSON,
			contentType: testResponseMediaType,
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
			kind: ErrorKindJSON,
		},
		{
			name:        "missing leases",
			body:        `{"enabled":false}`,
			contentType: testResponseMediaType,
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
			kind: ErrorKindJSON,
		},
		{
			name:        "missing lease field",
			body:        `{"leases":[{"hostname":"laptop"}]}`,
			contentType: testResponseMediaType,
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
			kind: ErrorKindJSON,
		},
	}
}

// dhcpInvalidJSONContractCases returns interface, enum, and media-type cases.
//
// Returns:
//   - The remaining invalid response cases.
func dhcpInvalidJSONContractCases() []dhcpInvalidJSONCase {
	return []dhcpInvalidJSONCase{
		{
			name:        "missing interface field",
			body:        `{"eth0":{"name":"eth0"}}`,
			contentType: testResponseMediaType,
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPInterfaces(ctx)

				return err
			},
			kind: ErrorKindJSON,
		},
		{
			name:        "invalid search enum",
			body:        `{"v4":{"other_server":{"found":"maybe"}}}`,
			contentType: testResponseMediaType,
			method:      http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPFindActive(ctx, nil)

				return err
			},
			kind: ErrorKindJSON,
		},
		{
			name:        "wrong content type",
			body:        `{"leases":[]}`,
			contentType: filteringTextPlainMediaType,
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
			kind: ErrorKindContentType,
		},
	}
}

// testDHCPInvalidJSONCase verifies one invalid-response case.
//
// Parameters:
//   - test: The invalid-response case to exercise.
func testDHCPInvalidJSONCase(t *testing.T, test dhcpInvalidJSONCase) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", test.contentType)
		writeBody(w, test.body)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	err := test.call(t.Context(), client)

	clientErr := requireClientError(t, err, test.kind)
	assert.Equal(t, test.method, clientErr.Method)
}

// TestClientDHCPStatusErrors verifies non-success status responses for DHCP
// operations.
func TestClientDHCPStatusErrors(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpStatusErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			testDHCPStatusErrorCase(t, test)
		})
	}
}

// dhcpStatusErrorCases returns DHCP operations with non-success responses.
//
// Returns:
//   - The status, interfaces, config, search, lease, and reset cases.
func dhcpStatusErrorCases() []dhcpStatusErrorCase {
	return []dhcpStatusErrorCase{
		{
			name:         "status unsupported",
			method:       http.MethodGet,
			statusCode:   http.StatusInternalServerError,
			expectedBody: dhcpNotImplementedBody,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
		},
		{
			name:         "interfaces unsupported",
			method:       http.MethodGet,
			statusCode:   http.StatusInternalServerError,
			expectedBody: dhcpNotImplementedBody,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPInterfaces(ctx)

				return err
			},
		},
		{
			name:         "config unsupported",
			method:       http.MethodPost,
			statusCode:   http.StatusNotImplemented,
			expectedBody: dhcpNotImplementedBody,
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPConfig(ctx, newDHCPEmptyConfig())
			},
		},
		{
			name:         "active search unsupported",
			method:       http.MethodPost,
			statusCode:   http.StatusNotImplemented,
			expectedBody: dhcpNotImplementedBody,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.DHCPFindActive(ctx, nil)

				return err
			},
		},
		{
			name:         "static lease unsupported",
			method:       http.MethodPost,
			statusCode:   http.StatusNotImplemented,
			expectedBody: dhcpNotImplementedBody,
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPAddStaticLease(ctx, newDHCPStaticLease())
			},
		},
		{
			name:         "reset unsupported",
			method:       http.MethodPost,
			statusCode:   http.StatusNotImplemented,
			expectedBody: dhcpNotImplementedBody,
			call: func(ctx context.Context, client *Client) error {
				return client.DHCPReset(ctx)
			},
		},
	}
}

// testDHCPStatusErrorCase verifies one non-success DHCP response.
//
// Parameters:
//   - test: The status-error case to exercise.
func testDHCPStatusErrorCase(t *testing.T, test dhcpStatusErrorCase) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testResponseMediaType)
		w.WriteHeader(test.statusCode)
		writeBody(w, `{"message":"`+test.expectedBody+`"}`)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	err := test.call(t.Context(), client)

	clientErr := requireClientError(t, err, ErrorKindStatus)
	assert.Equal(t, test.method, clientErr.Method)
	assert.Equal(t, test.statusCode, clientErr.StatusCode)
	assert.JSONEq(t, `{"message":"`+test.expectedBody+`"}`, string(clientErr.Body))
}

// TestClientDHCPLimitsAndCancellation verifies response limits and context
// cancellation.
func TestClientDHCPLimitsAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("response limit", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", testResponseMediaType)
			writeBody(w, `{"leases":[]}`)
		}))
		client := newDHCPTLSTestClient(t, server, 1)

		_, err := client.DHCPStatus(t.Context())

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, http.MethodGet, clientErr.Method)
		assert.Equal(t, int64(1), clientErr.Limit)
	})

	t.Run("no-content response limit", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			writeBody(w, `{}`)
		}))
		client := newDHCPTLSTestClient(t, server, 1)

		err := client.DHCPReset(t.Context())

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.Equal(t, int64(1), clientErr.Limit)
	})

	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		client := newDHCPTLSTestClient(t, server, 4096)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := client.DHCPReset(ctx)

		clientErr := requireClientError(t, err, ErrorKindRequest)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.ErrorIs(t, err, context.Canceled)
	})
}

// dhcpJSONMediaTypeValue returns the JSON media type used for request
// assertions.
//
// Returns:
//   - The JSON media type string.
func dhcpJSONMediaTypeValue() string {
	return testResponseMediaType
}

// newDHCPRequestCapture captures request metadata and body-read errors outside a handler.
//
// Parameters:
//   - r: The request received by the test server.
//   - body: The bytes read from the request body.
//   - err: The body-read error, if any.
//
// Returns:
//   - A request capture for assertions in the test goroutine.
func newDHCPRequestCapture(r *http.Request, body []byte, err error) dhcpRequestCapture {
	return dhcpRequestCapture{
		body:          body,
		contentLength: r.ContentLength,
		contentType:   r.Header.Get("Content-Type"),
		err:           err,
		method:        r.Method,
		path:          r.URL.Path,
	}
}

// newDHCPEmptyConfig returns a complete empty DHCP configuration fixture.
//
// Returns:
//   - A configuration whose fields are all absent.
func newDHCPEmptyConfig() *DHCPConfig {
	return &DHCPConfig{
		Enabled:       nil,
		InterfaceName: nil,
		V4:            nil,
		V6:            nil,
	}
}

// newDHCPExplicitZeroConfig returns a complete explicit-zero DHCP
// configuration fixture.
//
// Returns:
//   - A configuration containing explicit zero and empty values.
func newDHCPExplicitZeroConfig() *DHCPConfig {
	return &DHCPConfig{
		Enabled:       new(false),
		InterfaceName: new(dhcpTestInterfaceName),
		V4: &DHCPConfigV4{
			GatewayIP:     new(""),
			SubnetMask:    nil,
			RangeStart:    nil,
			RangeEnd:      nil,
			LeaseDuration: new(int64(0)),
		},
		V6: &DHCPConfigV6{
			RangeStart:    nil,
			LeaseDuration: nil,
		},
	}
}

// newDHCPEmptyFindRequest returns a complete empty active-search request
// fixture.
//
// Returns:
//   - A request whose interface field is absent.
func newDHCPEmptyFindRequest() *DHCPFindRequest {
	return &DHCPFindRequest{
		Interface: nil,
	}
}

// newDHCPStaticLease returns a complete static-lease fixture.
//
// Returns:
//   - The static lease used by add and remove requests.
func newDHCPStaticLease() DHCPStaticLease {
	return DHCPStaticLease{
		Hostname: dhcpTestPrinterHostname,
		IP:       dhcpTestPrinterIP,
		MAC:      dhcpTestPrinterMAC,
	}
}

// newDHCPUpdatedStaticLease returns a complete updated static-lease fixture.
//
// Returns:
//   - The replacement lease used by update requests.
func newDHCPUpdatedStaticLease() DHCPStaticLease {
	return DHCPStaticLease{
		Hostname: dhcpTestUpdatedHostname,
		IP:       dhcpTestUpdatedIP,
		MAC:      dhcpTestPrinterMAC,
	}
}

// newDHCPTLSTestClient creates a client bound to an in-memory test server.
//
// Parameters:
//   - server: The test server supplying the HTTP transport.
//   - limit: The maximum response body size.
//
// Returns:
//   - A configured AdGuard client.
func newDHCPTLSTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth(dhcpTestUsername, dhcpTestPassword),
		WithUserAgent(dhcpTestUserAgent),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// readDHCPTLSBody reads a request body for the shared TLS and DHCP test helpers.
//
// Parameters:
//   - r: The request whose body should be read.
//
// Returns:
//   - The request body as a string.
func readDHCPTLSBody(t *testing.T, r *http.Request) string {
	t.Helper()

	body, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	return string(body)
}
