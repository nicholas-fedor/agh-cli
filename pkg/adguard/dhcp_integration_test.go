// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// dhcpIntegrationRequestCapture carries request metadata across the handler boundary.
type dhcpIntegrationRequestCapture struct {
	// body contains the bytes read from the request body.
	body []byte
	// contentLength is the declared request body length.
	contentLength int64
	// contentType is the request body media type.
	contentType string
	// accept is the response media type requested by the client.
	accept string
	// userAgent is the request User-Agent.
	userAgent string
	// method is the HTTP request method.
	method string
	// path is the request URL path.
	path string
	// query is the request URL query.
	query string
	// username is the Basic Auth username.
	username string
	// password is the Basic Auth password.
	password string
	// authenticated reports whether Basic Auth was present.
	authenticated bool
	// err is the request body read error.
	err error
}

// dhcpIntegrationBodyMode describes whether a request carries a JSON body.
type dhcpIntegrationBodyMode uint8

// dhcpIntegrationConfigCase describes one DHCP configuration request.
type dhcpIntegrationConfigCase struct {
	// name identifies the subtest.
	name string
	// config is the optional request body.
	config *adguard.DHCPConfig
	// bodyMode reports whether the request must contain a JSON object.
	bodyMode dhcpIntegrationBodyMode
	// expectedBody is the decoded request body when one is expected.
	expectedBody map[string]any
	// responseBody is the optional response body.
	responseBody string
}

// dhcpIntegrationFindCase describes one DHCP active-search request.
type dhcpIntegrationFindCase struct {
	// name identifies the subtest.
	name string
	// request is the optional request body.
	request *adguard.DHCPFindRequest
	// bodyMode reports whether the request must contain a JSON object.
	bodyMode dhcpIntegrationBodyMode
	// expectedBody is the decoded request body when one is expected.
	expectedBody map[string]any
}

// dhcpIntegrationLeaseMutationCase describes one static-lease mutation.
type dhcpIntegrationLeaseMutationCase struct {
	// name identifies the subtest.
	name string
	// path is the expected endpoint path.
	path string
	// expectedBody is the exact serialized request body.
	expectedBody string
	// call invokes the static-lease operation.
	call func(context.Context, *adguard.Client) error
}

// dhcpIntegrationInvalidResponseCase describes one invalid DHCP response.
type dhcpIntegrationInvalidResponseCase struct {
	// name identifies the subtest.
	name string
	// body is the response JSON body.
	body string
	// method is the expected structured error method.
	method string
	// operation is the expected structured error operation.
	operation string
	// call invokes the DHCP operation.
	call func(context.Context, *adguard.Client) error
}

// dhcpIntegrationStatusErrorCase describes one non-success DHCP response.
type dhcpIntegrationStatusErrorCase struct {
	// name identifies the subtest.
	name string
	// operation is the expected structured error operation.
	operation string
	// method is the expected HTTP method and structured error method.
	method string
	// path is the expected endpoint path.
	path string
	// bodyMode reports whether the request must contain a JSON object.
	bodyMode dhcpIntegrationBodyMode
	// call invokes the DHCP operation.
	call func(context.Context, *adguard.Client) error
}

const (
	// DhcpIntegrationBodyAbsent indicates that a request must omit its body.
	dhcpIntegrationBodyAbsent dhcpIntegrationBodyMode = iota
	// DhcpIntegrationBodyPresent indicates that a request must contain a JSON object.
	dhcpIntegrationBodyPresent
)

const (
	// DhcpIntegrationStatusOperation identifies DHCP status errors.
	dhcpIntegrationStatusOperation = "dhcp_status"
	// DhcpIntegrationInterfacesOperation identifies DHCP interface errors.
	dhcpIntegrationInterfacesOperation = "dhcp_interfaces"
	// DhcpIntegrationConfigOperation identifies DHCP configuration errors.
	dhcpIntegrationConfigOperation = "dhcp_config"
	// DhcpIntegrationFindActiveOperation identifies active-search errors.
	dhcpIntegrationFindActiveOperation = "dhcp_find_active"
	// DhcpIntegrationAddStaticLeaseOperation identifies static-lease add errors.
	dhcpIntegrationAddStaticLeaseOperation = "dhcp_add_static_lease"
	// DhcpIntegrationRemoveStaticLeaseOperation identifies static-lease remove errors.
	dhcpIntegrationRemoveStaticLeaseOperation = "dhcp_remove_static_lease"
	// DhcpIntegrationUpdateStaticLeaseOperation identifies static-lease update errors.
	dhcpIntegrationUpdateStaticLeaseOperation = "dhcp_update_static_lease"
	// DhcpIntegrationResetOperation identifies DHCP reset errors.
	dhcpIntegrationResetOperation = "dhcp_reset"
	// DhcpIntegrationResetLeasesOperation identifies DHCP lease-reset errors.
	dhcpIntegrationResetLeasesOperation = "dhcp_reset_leases"
	// DhcpIntegrationUserAgent is the User-Agent used by DHCP integration tests.
	dhcpIntegrationUserAgent = "adguard-dhcp-integration-test/1.0"
	// DhcpIntegrationUsername is the Basic Auth username used by DHCP tests.
	dhcpIntegrationUsername = "dhcp-integration-user"
	// DhcpIntegrationPassword is the Basic Auth password used by DHCP tests.
	dhcpIntegrationPassword = "dhcp-integration-password"
	// DhcpIntegrationInterfaceName is the interface used by request fixtures.
	dhcpIntegrationInterfaceName = "eth0"
	// DhcpIntegrationLeaseHostname is the static-lease hostname fixture.
	dhcpIntegrationLeaseHostname = "printer"
	// DhcpIntegrationUpdatedLeaseHostname is the replacement static-lease hostname.
	dhcpIntegrationUpdatedLeaseHostname = "printer-new"
	// DhcpIntegrationUpdatedLeaseIP is the replacement static-lease address.
	dhcpIntegrationUpdatedLeaseIP = "192.0.2.21"
	// DhcpIntegrationLeaseMAC is the static-lease hardware address fixture.
	dhcpIntegrationLeaseMAC = "00:11:22:33:44:66"
	// AdguardIntegrationGatewayIP is the shared loopback gateway fixture address.
	adguardIntegrationGatewayIP = "192.0.2.1"
	// DhcpIntegrationStatusBody is the successful DHCP status response.
	dhcpIntegrationStatusBody = `{
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
	}`
	// DhcpIntegrationFindBody is the successful active-search response.
	dhcpIntegrationFindBody = `{
		"v4":{
			"other_server":{"found":"no","error":null},
			"static_ip":{"static":"yes","ip":"192.0.2.10"}
		},
		"v6":{"other_server":{"found":"error","error":"timeout"}}
	}`
	// DhcpIntegrationStatusErrorBody is the non-success response body.
	dhcpIntegrationStatusErrorBody = `{"message":"maintenance"}`
)

// TestDHCPIntegrationStatus verifies DHCP status request metadata and decoding.
func TestDHCPIntegrationStatus(t *testing.T) {
	t.Parallel()

	captured := make(chan dhcpIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureDHCPIntegrationRequest(r)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeDHCPIntegrationBody(w, dhcpIntegrationStatusBody)
	}))
	client := newDHCPIntegrationClient(t, server)

	status, err := client.DHCPStatus(t.Context())
	request := <-captured

	assertDHCPIntegrationRequest(t, request, http.MethodGet, "/api/control/dhcp/status", dhcpIntegrationBodyAbsent)
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
	assert.Equal(t, adguard.DHCPLease{
		Expires:  "2026-09-25T01:00:00Z",
		Hostname: "laptop",
		IP:       clientsIntegrationDeskID,
		MAC:      "00:11:22:33:44:55",
	}, status.Leases[0])
	require.NotNil(t, status.StaticLeases)
	assert.Empty(t, *status.StaticLeases)
}

// TestDHCPIntegrationInterfaces verifies DHCP interface request metadata and decoding.
func TestDHCPIntegrationInterfaces(t *testing.T) {
	t.Parallel()

	captured := make(chan dhcpIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureDHCPIntegrationRequest(r)

		w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
		writeDHCPIntegrationBody(w, `{
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
	client := newDHCPIntegrationClient(t, server)

	interfaces, err := client.DHCPInterfaces(t.Context())
	request := <-captured

	assertDHCPIntegrationRequest(t, request, http.MethodGet, "/api/control/dhcp/interfaces", dhcpIntegrationBodyAbsent)
	require.NoError(t, err)
	assert.Equal(t, map[string]adguard.DHCPInterface{
		dhcpIntegrationInterfaceName: {
			Flags:           "up|broadcast|multicast",
			GatewayIP:       adguardIntegrationGatewayIP,
			HardwareAddress: "52:54:00:12:34:56",
			IPv4Addresses:   []string{"192.0.2.10/24"},
			IPv6Addresses:   []string{"2001:db8::10/64"},
			Name:            dhcpIntegrationInterfaceName,
		},
	}, interfaces)
}

// TestDHCPIntegrationConfig verifies omitted and explicit configuration bodies.
func TestDHCPIntegrationConfig(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpIntegrationConfigCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runDHCPIntegrationConfigCase(t, test)
		})
	}
}

// dhcpIntegrationConfigCases returns DHCP configuration request cases.
//
// Returns:
//   - The configuration request cases.
func dhcpIntegrationConfigCases() []dhcpIntegrationConfigCase {
	return []dhcpIntegrationConfigCase{
		{
			name:         "omitted body accepts JSON response",
			config:       nil,
			bodyMode:     dhcpIntegrationBodyAbsent,
			expectedBody: nil,
			responseBody: `{"accepted":true}`,
		},
		{
			name:         "empty object accepts empty response",
			config:       &adguard.DHCPConfig{},
			bodyMode:     dhcpIntegrationBodyPresent,
			expectedBody: map[string]any{},
			responseBody: "",
		},
		{
			name:         "explicit values preserve presence",
			config:       newDHCPIntegrationConfig(),
			bodyMode:     dhcpIntegrationBodyPresent,
			expectedBody: dhcpIntegrationConfigExpectedBody(),
			responseBody: "",
		},
	}
}

// runDHCPIntegrationConfigCase verifies one DHCP configuration request.
//
// Parameters:
//   - test: The configuration request case to exercise.
func runDHCPIntegrationConfigCase(t *testing.T, test dhcpIntegrationConfigCase) {
	t.Helper()

	captured := make(chan dhcpIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureDHCPIntegrationRequest(r)
		if test.responseBody == "" {
			w.WriteHeader(http.StatusNoContent)

			return
		}

		w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
		writeDHCPIntegrationBody(w, test.responseBody)
	}))
	client := newDHCPIntegrationClient(t, server)

	err := client.DHCPConfig(t.Context(), test.config)
	request := <-captured

	assertDHCPIntegrationRequest(t, request, http.MethodPost, "/api/control/dhcp/set_config", test.bodyMode)
	require.NoError(t, err)

	if test.bodyMode == dhcpIntegrationBodyAbsent {
		return
	}

	var body map[string]any

	require.NoError(t, json.Unmarshal(request.body, &body))
	assert.Equal(t, test.expectedBody, body)
}

// TestDHCPIntegrationFindActive verifies active-search request presence and decoding.
func TestDHCPIntegrationFindActive(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpIntegrationFindCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runDHCPIntegrationFindCase(t, test)
		})
	}
}

// dhcpIntegrationFindCases returns active-search request cases.
//
// Returns:
//   - The active-search request cases.
func dhcpIntegrationFindCases() []dhcpIntegrationFindCase {
	interfaceName := dhcpIntegrationInterfaceName

	return []dhcpIntegrationFindCase{
		{
			name:         "omitted body",
			request:      nil,
			bodyMode:     dhcpIntegrationBodyAbsent,
			expectedBody: nil,
		},
		{
			name:         "empty object",
			request:      &adguard.DHCPFindRequest{},
			bodyMode:     dhcpIntegrationBodyPresent,
			expectedBody: map[string]any{},
		},
		{
			name: "interface present",
			request: &adguard.DHCPFindRequest{
				Interface: &interfaceName,
			},
			bodyMode: dhcpIntegrationBodyPresent,
			expectedBody: map[string]any{
				"interface": dhcpIntegrationInterfaceName,
			},
		},
	}
}

// runDHCPIntegrationFindCase verifies one active-search request and response.
//
// Parameters:
//   - test: The active-search request case to exercise.
func runDHCPIntegrationFindCase(t *testing.T, test dhcpIntegrationFindCase) {
	t.Helper()

	captured := make(chan dhcpIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureDHCPIntegrationRequest(r)

		w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
		writeDHCPIntegrationBody(w, dhcpIntegrationFindBody)
	}))
	client := newDHCPIntegrationClient(t, server)

	result, err := client.DHCPFindActive(t.Context(), test.request)
	request := <-captured

	assertDHCPIntegrationRequest(t, request, http.MethodPost, "/api/control/dhcp/find_active_dhcp", test.bodyMode)
	require.NoError(t, err)

	if test.bodyMode == dhcpIntegrationBodyPresent {
		var body map[string]any

		require.NoError(t, json.Unmarshal(request.body, &body))
		assert.Equal(t, test.expectedBody, body)
	}

	require.NotNil(t, result)
	require.NotNil(t, result.V4)
	require.NotNil(t, result.V4.OtherServer)
	require.NotNil(t, result.V4.OtherServer.Found)
	assert.Equal(t, adguard.DHCPSearchStatusNo, *result.V4.OtherServer.Found)
	assert.Nil(t, result.V4.OtherServer.Error)
	require.NotNil(t, result.V4.StaticIP)
	require.NotNil(t, result.V4.StaticIP.Status)
	assert.Equal(t, adguard.DHCPSearchStatusYes, *result.V4.StaticIP.Status)
	assert.Equal(t, "192.0.2.10", *result.V4.StaticIP.IP)
	require.NotNil(t, result.V6)
	require.NotNil(t, result.V6.OtherServer)
	require.NotNil(t, result.V6.OtherServer.Found)
	assert.Equal(t, adguard.DHCPSearchStatusError, *result.V6.OtherServer.Found)
	require.NotNil(t, result.V6.OtherServer.Error)
	assert.Equal(t, "timeout", *result.V6.OtherServer.Error)
}

// TestDHCPIntegrationStaticLeaseMutations verifies exact add, remove, and update requests.
func TestDHCPIntegrationStaticLeaseMutations(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpIntegrationLeaseMutationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan dhcpIntegrationRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured <- captureDHCPIntegrationRequest(r)

				w.WriteHeader(http.StatusNoContent)
			}))
			client := newDHCPIntegrationClient(t, server)

			err := test.call(t.Context(), client)
			request := <-captured

			assertDHCPIntegrationRequest(t, request, http.MethodPost, test.path, dhcpIntegrationBodyPresent)
			assert.Equal(t, test.expectedBody, string(request.body))
			require.NoError(t, err)
		})
	}
}

// dhcpIntegrationLeaseMutationCases returns static-lease mutation cases.
//
// Returns:
//   - The static-lease mutation cases.
func dhcpIntegrationLeaseMutationCases() []dhcpIntegrationLeaseMutationCase {
	return []dhcpIntegrationLeaseMutationCase{
		{
			name:         rewriteIntegrationAddName,
			path:         "/api/control/dhcp/add_static_lease",
			expectedBody: `{"hostname":"printer","ip":"192.0.2.20","mac":"00:11:22:33:44:66"}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPAddStaticLease(ctx, newDHCPIntegrationLease())
			},
		},
		{
			name:         "remove",
			path:         "/api/control/dhcp/remove_static_lease",
			expectedBody: `{"hostname":"printer","ip":"192.0.2.20","mac":"00:11:22:33:44:66"}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPRemoveStaticLease(ctx, newDHCPIntegrationLease())
			},
		},
		{
			name:         blockedServicesIntegrationUpdateName,
			path:         "/api/control/dhcp/update_static_lease",
			expectedBody: `{"hostname":"printer-new","ip":"192.0.2.21","mac":"00:11:22:33:44:66"}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPUpdateStaticLease(ctx, newDHCPIntegrationUpdatedLease())
			},
		},
	}
}

// TestDHCPIntegrationResets verifies bodyless reset requests and empty responses.
func TestDHCPIntegrationResets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		// name identifies the reset operation.
		name string
		// path is the expected endpoint path.
		path string
		// call invokes the reset operation.
		call func(context.Context, *adguard.Client) error
	}{
		{
			name: "configuration",
			path: "/api/control/dhcp/reset",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPReset(ctx)
			},
		},
		{
			name: "leases",
			path: "/api/control/dhcp/reset_leases",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPResetLeases(ctx)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan dhcpIntegrationRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured <- captureDHCPIntegrationRequest(r)

				w.WriteHeader(http.StatusNoContent)
			}))
			client := newDHCPIntegrationClient(t, server)

			err := test.call(t.Context(), client)
			request := <-captured

			assertDHCPIntegrationRequest(t, request, http.MethodPost, test.path, dhcpIntegrationBodyAbsent)
			require.NoError(t, err)
		})
	}
}

// TestDHCPIntegrationRejectsRequiredFields verifies structured response-contract errors.
func TestDHCPIntegrationRejectsRequiredFields(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpIntegrationInvalidResponseCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
				writeDHCPIntegrationBody(w, test.body)
			}))
			client := newDHCPIntegrationClient(t, server)

			err := test.call(t.Context(), client)
			clientErr := dhcpIntegrationRequireError(t, err, adguard.ErrorKindJSON)

			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
		})
	}
}

// dhcpIntegrationInvalidResponseCases returns required-field and JSON contract cases.
func dhcpIntegrationInvalidResponseCases() []dhcpIntegrationInvalidResponseCase {
	return []dhcpIntegrationInvalidResponseCase{
		{
			name:      "status missing leases",
			body:      integrationEnabledFalseJSON,
			method:    http.MethodGet,
			operation: dhcpIntegrationStatusOperation,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
		},
		{
			name: "status missing lease field",
			body: `{"leases":[{
				"expires":"2026-09-25T01:00:00Z",
				"hostname":"laptop",
				"ip":"192.0.2.10"
			}]}`,
			method:    http.MethodGet,
			operation: dhcpIntegrationStatusOperation,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
		},
		{
			name:      "status missing static lease field",
			body:      `{"leases":[],"static_leases":[{"hostname":"printer","ip":"192.0.2.20"}]}`,
			method:    http.MethodGet,
			operation: dhcpIntegrationStatusOperation,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
		},
		{
			name:      "interface missing required field",
			body:      `{"eth0":{"name":"eth0"}}`,
			method:    http.MethodGet,
			operation: dhcpIntegrationInterfacesOperation,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPInterfaces(ctx)

				return err
			},
		},
		{
			name:      "active search null response",
			body:      safetyIntegrationNullName,
			method:    http.MethodPost,
			operation: dhcpIntegrationFindActiveOperation,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPFindActive(ctx, nil)

				return err
			},
		},
		{
			name:      "malformed status response",
			body:      `{"leases":`,
			method:    http.MethodGet,
			operation: dhcpIntegrationStatusOperation,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
		},
	}
}

// TestDHCPIntegrationReportsStatusErrors verifies structured non-success responses.
func TestDHCPIntegrationReportsStatusErrors(t *testing.T) {
	t.Parallel()

	for _, test := range dhcpIntegrationStatusErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			runDHCPIntegrationStatusErrorCase(t, test)
		})
	}
}

// dhcpIntegrationStatusErrorCases returns non-success cases for every DHCP operation.
//
// Returns:
//   - The status-error cases.
func dhcpIntegrationStatusErrorCases() []dhcpIntegrationStatusErrorCase {
	cases := dhcpIntegrationReadStatusErrorCases()

	cases = append(cases, dhcpIntegrationConfigStatusErrorCases()...)

	return append(cases, dhcpIntegrationMutationStatusErrorCases()...)
}

// dhcpIntegrationReadStatusErrorCases returns status and interface error cases.
//
// Returns:
//   - The read-operation status-error cases.
func dhcpIntegrationReadStatusErrorCases() []dhcpIntegrationStatusErrorCase {
	return []dhcpIntegrationStatusErrorCase{
		{
			name:      filteringIntegrationStatusName,
			operation: dhcpIntegrationStatusOperation,
			method:    http.MethodGet,
			path:      "/api/control/dhcp/status",
			bodyMode:  dhcpIntegrationBodyAbsent,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPStatus(ctx)

				return err
			},
		},
		{
			name:      "interfaces",
			operation: dhcpIntegrationInterfacesOperation,
			method:    http.MethodGet,
			path:      "/api/control/dhcp/interfaces",
			bodyMode:  dhcpIntegrationBodyAbsent,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPInterfaces(ctx)

				return err
			},
		},
	}
}

// dhcpIntegrationConfigStatusErrorCases returns configuration and search error cases.
//
// Returns:
//   - The configuration and search status-error cases.
func dhcpIntegrationConfigStatusErrorCases() []dhcpIntegrationStatusErrorCase {
	return []dhcpIntegrationStatusErrorCase{
		{
			name:      "config",
			operation: dhcpIntegrationConfigOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/set_config",
			bodyMode:  dhcpIntegrationBodyAbsent,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPConfig(ctx, nil)
			},
		},
		{
			name:      "active search",
			operation: dhcpIntegrationFindActiveOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/find_active_dhcp",
			bodyMode:  dhcpIntegrationBodyAbsent,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DHCPFindActive(ctx, nil)

				return err
			},
		},
	}
}

// dhcpIntegrationMutationStatusErrorCases returns lease and reset error cases.
//
// Returns:
//   - The mutation status-error cases.
func dhcpIntegrationMutationStatusErrorCases() []dhcpIntegrationStatusErrorCase {
	return []dhcpIntegrationStatusErrorCase{
		{
			name:      "add static lease",
			operation: dhcpIntegrationAddStaticLeaseOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/add_static_lease",
			bodyMode:  dhcpIntegrationBodyPresent,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPAddStaticLease(ctx, newDHCPIntegrationLease())
			},
		},
		{
			name:      "remove static lease",
			operation: dhcpIntegrationRemoveStaticLeaseOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/remove_static_lease",
			bodyMode:  dhcpIntegrationBodyPresent,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPRemoveStaticLease(ctx, newDHCPIntegrationLease())
			},
		},
		{
			name:      "update static lease",
			operation: dhcpIntegrationUpdateStaticLeaseOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/update_static_lease",
			bodyMode:  dhcpIntegrationBodyPresent,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPUpdateStaticLease(ctx, newDHCPIntegrationUpdatedLease())
			},
		},
		{
			name:      "reset configuration",
			operation: dhcpIntegrationResetOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/reset",
			bodyMode:  dhcpIntegrationBodyAbsent,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPReset(ctx)
			},
		},
		{
			name:      "reset leases",
			operation: dhcpIntegrationResetLeasesOperation,
			method:    http.MethodPost,
			path:      "/api/control/dhcp/reset_leases",
			bodyMode:  dhcpIntegrationBodyAbsent,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DHCPResetLeases(ctx)
			},
		},
	}
}

// runDHCPIntegrationStatusErrorCase verifies one non-success DHCP response.
//
// Parameters:
//   - test: The status-error case to exercise.
func runDHCPIntegrationStatusErrorCase(t *testing.T, test dhcpIntegrationStatusErrorCase) {
	t.Helper()

	captured := make(chan dhcpIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureDHCPIntegrationRequest(r)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		writeDHCPIntegrationBody(w, dhcpIntegrationStatusErrorBody)
	}))
	client := newDHCPIntegrationClient(t, server)

	err := test.call(t.Context(), client)
	request := <-captured
	assertDHCPIntegrationRequest(t, request, test.method, test.path, test.bodyMode)

	clientErr := dhcpIntegrationRequireError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, test.operation, clientErr.Operation)
	assert.Equal(t, test.method, clientErr.Method)
	assert.Equal(t, http.StatusServiceUnavailable, clientErr.StatusCode)
	assert.Equal(t, "503 Service Unavailable", clientErr.Status)
	assert.Equal(t, "application/json; charset=utf-8", clientErr.ContentType)
	assert.JSONEq(t, dhcpIntegrationStatusErrorBody, string(clientErr.Body))
}

// newDHCPIntegrationClient creates a concrete client bound to a test server.
//
// Parameters:
//   - server: The in-memory test server whose transport should be used.
//
// Returns:
//   - A configured concrete AdGuard client.
func newDHCPIntegrationClient(t *testing.T, server *httptest.Server) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		blockedServicesIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(dhcpIntegrationUsername, dhcpIntegrationPassword),
		adguard.WithUserAgent(dhcpIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(4096),
	)
	require.NoError(t, err)

	return client
}

// captureDHCPIntegrationRequest reads request metadata and body bytes.
//
// Parameters:
//   - r: The incoming HTTP request to capture.
//
// Returns:
//   - The captured request metadata and body.
func captureDHCPIntegrationRequest(r *http.Request) dhcpIntegrationRequestCapture {
	body, err := io.ReadAll(r.Body)
	username, password, authenticated := r.BasicAuth()

	return dhcpIntegrationRequestCapture{
		body:          body,
		contentLength: r.ContentLength,
		contentType:   r.Header.Get("Content-Type"),
		accept:        r.Header.Get("Accept"),
		userAgent:     r.Header.Get("User-Agent"),
		method:        r.Method,
		path:          r.URL.Path,
		query:         r.URL.RawQuery,
		username:      username,
		password:      password,
		authenticated: authenticated,
		err:           err,
	}
}

// assertDHCPIntegrationRequest verifies common request metadata and body presence.
//
// Parameters:
//   - request: The captured request to verify.
//   - method: The expected HTTP method.
//   - path: The expected request path.
//   - bodyMode: The expected request body mode.
func assertDHCPIntegrationRequest(
	t *testing.T,
	request dhcpIntegrationRequestCapture,
	method string,
	path string,
	bodyMode dhcpIntegrationBodyMode,
) {
	t.Helper()

	require.NoError(t, request.err)
	assert.Equal(t, method, request.method)
	assert.Equal(t, path, request.path)
	assert.Empty(t, request.query)
	assert.True(t, request.authenticated)
	assert.Equal(t, dhcpIntegrationUsername, request.username)
	assert.Equal(t, dhcpIntegrationPassword, request.password)
	assert.Equal(t, "application/json", request.accept)
	assert.Equal(t, dhcpIntegrationUserAgent, request.userAgent)

	if bodyMode == dhcpIntegrationBodyPresent {
		assert.Positive(t, request.contentLength)
		assert.Equal(t, "application/json", request.contentType)
	} else {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.body)
		assert.Empty(t, request.contentType)
	}
}

// writeDHCPIntegrationBody writes a response body while tolerating disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeDHCPIntegrationBody(w http.ResponseWriter, body string) {
	_, err := io.WriteString(w, body)
	if err != nil {
		return
	}
}

// dhcpIntegrationRequireError extracts and verifies a structured client error.
//
// Parameters:
//   - err: The operation error to inspect.
//   - kind: The expected structured error kind.
//
// Returns:
//   - The extracted structured client error.
func dhcpIntegrationRequireError(
	t *testing.T,
	err error,
	kind adguard.ErrorKind,
) *adguard.Error {
	t.Helper()

	clientErr, ok := errors.AsType[*adguard.Error](err)
	if !ok {
		t.Fatalf("expected *adguard.Error, got %T", err)
	}

	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}

// newDHCPIntegrationConfig returns an explicit-value DHCP configuration fixture.
//
// Returns:
//   - A DHCP configuration containing explicit zero and string values.
func newDHCPIntegrationConfig() *adguard.DHCPConfig {
	return &adguard.DHCPConfig{
		Enabled:       new(false),
		InterfaceName: new(dhcpIntegrationInterfaceName),
		V4: &adguard.DHCPConfigV4{
			GatewayIP:     new(""),
			SubnetMask:    nil,
			RangeStart:    nil,
			RangeEnd:      nil,
			LeaseDuration: new(int64(0)),
		},
		V6: &adguard.DHCPConfigV6{
			RangeStart:    nil,
			LeaseDuration: nil,
		},
	}
}

// dhcpIntegrationConfigExpectedBody returns the expected explicit configuration JSON.
//
// Returns:
//   - The decoded request body expected for the explicit configuration.
func dhcpIntegrationConfigExpectedBody() map[string]any {
	return map[string]any{
		"enabled":        false,
		"interface_name": dhcpIntegrationInterfaceName,
		"v4": map[string]any{
			"gateway_ip":     "",
			"lease_duration": float64(0),
		},
		"v6": map[string]any{},
	}
}

// newDHCPIntegrationLease returns a complete static-lease fixture.
//
// Returns:
//   - A complete static DHCP lease.
func newDHCPIntegrationLease() adguard.DHCPStaticLease {
	return adguard.DHCPStaticLease{
		Hostname: dhcpIntegrationLeaseHostname,
		IP:       clientsIntegrationLaptopIP,
		MAC:      dhcpIntegrationLeaseMAC,
	}
}

// newDHCPIntegrationUpdatedLease returns a replacement static-lease fixture.
//
// Returns:
//   - A replacement static DHCP lease.
func newDHCPIntegrationUpdatedLease() adguard.DHCPStaticLease {
	return adguard.DHCPStaticLease{
		Hostname: dhcpIntegrationUpdatedLeaseHostname,
		IP:       dhcpIntegrationUpdatedLeaseIP,
		MAC:      dhcpIntegrationLeaseMAC,
	}
}
