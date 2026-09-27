// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// dhcpFuzzState contains the deterministic client and captured requests.
type dhcpFuzzState struct {
	// captures contains requests observed by the deterministic transport.
	captures []fuzzRequestCapture
	// client performs DHCP operations without external network access.
	client *Client
}

const (
	// Request fuzzing bounds derived DHCP strings.
	dhcpFuzzMaxRequestBytes = 128
	// Response fuzzing bounds DHCP JSON parsing.
	dhcpFuzzMaxResponseBytes = 8 << 10
)

// FuzzDHCPRequestResponse verifies DHCP request encoding and response contract validation.
func FuzzDHCPRequestResponse(f *testing.F) {
	f.Add([]byte{}, []byte(`{"leases":[]}`))
	f.Add([]byte("eth0"), []byte(`{
		"enabled":false,
		"interface_name":"eth0",
		"v4":{"gateway_ip":"192.0.2.1","lease_duration":0},
		"leases":[],"static_leases":[]
	}`))
	f.Add([]byte("printer"), []byte(`{}`))
	f.Add([]byte("invalid"), []byte(`{
		"v4":{"other_server":{"found":"maybe"}},
		"v6":{"other_server":{"found":"error","error":"timeout"}}
	}`))
	f.Add([]byte{0xff}, []byte(`null`))
	f.Add([]byte("eth0"), []byte(`{"leases":`))

	f.Fuzz(func(t *testing.T, requestData, responseData []byte) {
		exerciseDHCPFuzz(t, requestData, responseData)
	})
}

// exerciseDHCPFuzz exercises one bounded DHCP request and response pair.
//
// Parameters:
//   - requestData: The fuzz-derived request bytes.
//   - responseData: The fuzz-derived response bytes.
func exerciseDHCPFuzz(t *testing.T, requestData, responseData []byte) {
	t.Helper()

	requestData = boundedFuzzInput(requestData, dhcpFuzzMaxRequestBytes)
	responseData = boundedFuzzInput(responseData, dhcpFuzzMaxResponseBytes)

	state := newDHCPOfflineClient(t, responseData)

	requireDHCPConfigRequest(t, state.client, fuzzDHCPConfig(requestData))
	requireDHCPLeaseRequest(t, state.client, fuzzDHCPStaticLease(requestData))
	requireDHCPPublicResponses(t, state, requestData)
	requireDHCPCaptures(t, state.captures)
}

// newDHCPOfflineClient creates an offline DHCP client that records every request.
//
// Parameters:
//   - responseData: The bounded JSON body returned for every operation.
//
// Returns:
//   - state: The deterministic client and its captured requests.
func newDHCPOfflineClient(t *testing.T, responseData []byte) *dhcpFuzzState {
	t.Helper()

	state := &dhcpFuzzState{
		captures: make([]fuzzRequestCapture, 0, 5),
		client:   nil,
	}
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		state.captures = append(state.captures, capture)

		return fuzzHTTPResponse(
			request,
			http.StatusOK,
			testResponseMediaType,
			responseData,
		), nil
	})

	state.client = newFuzzClient(
		t,
		transport,
		max(int64(1), int64(len(responseData))),
	)

	return state
}

// requireDHCPConfigRequest exercises a bounded DHCP configuration request.
//
// Parameters:
//   - client: The deterministic AdGuard client.
//   - config: The fuzz-derived configuration, or nil for an omitted body.
func requireDHCPConfigRequest(t *testing.T, client *Client, config *DHCPConfig) {
	t.Helper()

	err := client.DHCPConfig(t.Context(), config)
	if err == nil {
		return
	}

	clientErr := requireFuzzError(
		t,
		err,
		ErrorKindRequest,
		dhcpConfigOperation,
		http.MethodPost,
	)
	require.Error(t, clientErr.Err)
}

// requireDHCPLeaseRequest exercises a bounded static-lease request.
//
// Parameters:
//   - client: The deterministic AdGuard client.
//   - lease: The fuzz-derived static lease.
func requireDHCPLeaseRequest(t *testing.T, client *Client, lease DHCPStaticLease) {
	t.Helper()

	err := client.DHCPAddStaticLease(t.Context(), lease)
	if err == nil {
		return
	}

	clientErr := requireFuzzError(
		t,
		err,
		ErrorKindRequest,
		dhcpAddStaticLeaseOperation,
		http.MethodPost,
	)
	require.Error(t, clientErr.Err)
}

// requireDHCPPublicResponses exercises status, interface, and active-search responses.
//
// Parameters:
//   - state: The deterministic client and captured requests.
//   - requestData: The bounded active-search request input.
func requireDHCPPublicResponses(t *testing.T, state *dhcpFuzzState, requestData []byte) {
	t.Helper()

	status, err := state.client.DHCPStatus(t.Context())
	requireFuzzJSONResult(t, status, err, dhcpStatusOperation, http.MethodGet)
	requireDHCPInterfaces(t, state.client)
	requireDHCPFindActive(t, state, fuzzDHCPFindRequest(requestData))
}

// requireDHCPInterfaces verifies the interface-map result-or-error contract.
//
// Parameters:
//   - client: The deterministic AdGuard client.
func requireDHCPInterfaces(t *testing.T, client *Client) {
	t.Helper()

	interfaces, err := client.DHCPInterfaces(t.Context())
	if err == nil {
		require.NotNil(t, interfaces)

		return
	}

	clientErr := requireFuzzError(
		t,
		err,
		ErrorKindJSON,
		dhcpInterfacesOperation,
		http.MethodGet,
	)
	require.Error(t, clientErr.Err)
}

// requireDHCPFindActive verifies the active-search result-or-error contract.
//
// Parameters:
//   - state: The deterministic client and captured requests.
//   - request: The fuzz-derived search request, or nil for an omitted body.
func requireDHCPFindActive(
	t *testing.T,
	state *dhcpFuzzState,
	request *DHCPFindRequest,
) {
	t.Helper()

	capturesBefore := len(state.captures)
	result, err := state.client.DHCPFindActive(t.Context(), request)
	kind := ErrorKindJSON
	if len(state.captures) == capturesBefore {
		kind = ErrorKindRequest
	}

	requireFuzzResult(
		t,
		result,
		err,
		kind,
		dhcpFindActiveOperation,
		http.MethodPost,
	)
}

// requireDHCPCaptures verifies every request observed by the deterministic transport.
//
// Parameters:
//   - captures: The captured DHCP requests.
func requireDHCPCaptures(t *testing.T, captures []fuzzRequestCapture) {
	t.Helper()

	for _, capture := range captures {
		requireDHCPCapture(t, capture)
	}
}

// requireDHCPCapture verifies that one exercised DHCP endpoint received a bounded request.
//
// Parameters:
//   - capture: The captured DHCP request to inspect.
func requireDHCPCapture(t *testing.T, capture fuzzRequestCapture) {
	t.Helper()

	switch capture.path {
	case "/api/control/dhcp/set_config",
		"/api/control/dhcp/add_static_lease",
		"/api/control/dhcp/find_active_dhcp":
		assert.Equal(t, http.MethodPost, capture.method)
	case "/api/control/dhcp/status", "/api/control/dhcp/interfaces":
		assert.Equal(t, http.MethodGet, capture.method)
	default:
		t.Errorf("unexpected DHCP fuzz path %q", capture.path)
	}

	assert.Empty(t, capture.query)
	requireFuzzJSONBody(t, capture)
}

// fuzzDHCPConfig derives a bounded nested DHCP configuration request.
//
// Parameters:
//   - data: The bounded request input.
//
// Returns:
//   - config: Nil for an omitted body, or a fuzz-derived configuration otherwise.
func fuzzDHCPConfig(data []byte) *DHCPConfig {
	if len(data) == 0 {
		return nil
	}

	interfaceName := string(data)
	gatewayIP := string(data)
	subnetMask := string(data)
	rangeStart := string(data)
	rangeEnd := string(data)
	rangeStartV6 := string(data)
	leaseDuration := int64(data[0])

	return &DHCPConfig{
		Enabled:       new(data[0]&0b01 == 0),
		InterfaceName: &interfaceName,
		V4: &DHCPConfigV4{
			GatewayIP:     &gatewayIP,
			SubnetMask:    &subnetMask,
			RangeStart:    &rangeStart,
			RangeEnd:      &rangeEnd,
			LeaseDuration: &leaseDuration,
		},
		V6: &DHCPConfigV6{
			RangeStart:    &rangeStartV6,
			LeaseDuration: &leaseDuration,
		},
	}
}

// fuzzDHCPFindRequest derives a bounded optional active-search request.
//
// Parameters:
//   - data: The bounded request input.
//
// Returns:
//   - request: Nil for an omitted body, or a fuzz-derived search request otherwise.
func fuzzDHCPFindRequest(data []byte) *DHCPFindRequest {
	if len(data) < 2 || data[0]&0b01 == 0 {
		return nil
	}

	interfaceName := string(data[1:])

	return &DHCPFindRequest{Interface: &interfaceName}
}

// fuzzDHCPStaticLease derives a bounded static-lease request.
//
// Parameters:
//   - data: The bounded request input.
//
// Returns:
//   - lease: A fuzz-derived static lease.
func fuzzDHCPStaticLease(data []byte) DHCPStaticLease {
	return DHCPStaticLease{
		Hostname: string(data),
		IP:       string(data),
		MAC:      string(data),
	}
}
