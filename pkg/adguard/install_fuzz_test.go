// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"encoding/json/v2"
	"net/http"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// installFuzzOperation describes one public installation operation.
type installFuzzOperation struct {
	// jsonResponse reports whether a successful response requires JSON.
	jsonResponse bool
	// method is the expected HTTP method.
	method string
	// name is the structured client operation name.
	name string
	// path is the expected endpoint path.
	path string
}

// installFuzzSeed describes one deterministic response fixture.
type installFuzzSeed struct {
	// body contains the bounded response payload.
	body []byte
	// mode selects the response policy.
	mode byte
	// operation selects the public operation.
	operation byte
}

// installFuzzState contains deterministic installation fuzz state.
type installFuzzState struct {
	// captures contains requests observed by the deterministic transport.
	captures []fuzzRequestCapture
	// client performs installation operations without network access.
	client *Client
	// limit is the deterministic response body limit.
	limit int64
	// mode selects the deterministic response policy.
	mode byte
	// operation identifies the selected public operation.
	operation installFuzzOperation
	// response contains the bounded response body.
	response []byte
}

const (
	// Install request fuzzing bounds encoded string values.
	installFuzzMaxRequestBytes = 256
	// Install response fuzzing bounds JSON decoding and allocation.
	installFuzzMaxResponseBytes = 8 << 10
	// Install fuzz redirects remain inside the injected transport.
	installFuzzRedirectLocation = "https://fuzz.invalid/install-redirect"
	// Install opaque responses exercise the body-agnostic mode.
	installFuzzTextMediaType = "text/plain; charset=utf-8"
	// Response fixture installFuzzValidCheckResponse is minimally valid.
	installFuzzValidCheckResponse = `{
		"dns":{"status":"","can_autofix":false},
		"web":{"status":"","can_autofix":false},
		"static_ip":{}
	}`
	// Response fixture installFuzzValidAddressesResponse is minimally complete.
	installFuzzValidAddressesResponse = `{
		"dns_port":53,
		"interfaces":{
			"eth0":{
				"flags":"up|broadcast|running",
				"gateway_ip":"192.0.2.1",
				"hardware_address":"00:11:22:33:44:55",
				"ipv4_addresses":["192.0.2.10"],
				"ipv6_addresses":["2001:db8::10"],
				"name":"eth0"
			}
		},
		"version":"v0.107.52",
		"web_port":3000
	}`
)

const (
	// Response mode installFuzzJSON returns a successful JSON response.
	installFuzzJSON byte = iota
	// Response mode installFuzzOpaque returns a successful non-JSON response.
	installFuzzOpaque
	// Response mode installFuzzStatus returns a non-success response.
	installFuzzStatus
	// Response mode installFuzzRedirect returns a client-rejected redirect.
	installFuzzRedirect
	// Response mode installFuzzTooLarge exceeds the configured limit.
	installFuzzTooLarge
)

// FuzzInstallResponses exercises installation response modes, redirects, and validation.
func FuzzInstallResponses(f *testing.F) {
	addInstallResponseFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, operation, mode byte, body []byte) {
		exerciseInstallResponseFuzz(t, operation, mode, body)
	})
}

// FuzzInstallRequestPresence exercises request body presence and optional-field encoding.
func FuzzInstallRequestPresence(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x07})
	f.Add([]byte{0x3f, 0xff, 0xff, 0xff, 'i', 'n', 's', 't', 'a', 'l', 'l'})
	f.Add([]byte("edge"))
	f.Add([]byte("900Ў"))

	f.Fuzz(func(t *testing.T, data []byte) {
		exerciseInstallRequestFuzz(t, data)
	})
}

// addInstallResponseFuzzSeeds registers deterministic bounded response fixtures.
func addInstallResponseFuzzSeeds(f *testing.F) {
	f.Helper()
	addInstallAddressesResponseFuzzSeeds(f)
	addInstallCheckResponseFuzzSeeds(f)
	addInstallConfigureResponseFuzzSeeds(f)
}

// addInstallAddressesResponseFuzzSeeds registers address-response fixtures.
func addInstallAddressesResponseFuzzSeeds(f *testing.F) {
	f.Helper()

	addInstallFuzzSeeds(f, []installFuzzSeed{
		{
			body:      []byte(installFuzzValidAddressesResponse),
			mode:      installFuzzJSON,
			operation: 0,
		},
		{
			body:      []byte(`{"dns_port":0,"interfaces":{},"version":"","web_port":65535}`),
			mode:      installFuzzJSON,
			operation: 0,
		},
		{body: []byte(`null`), mode: installFuzzJSON, operation: 0},
		{
			body:      []byte(`{"dns_port":53,"version":"v0.107.52","web_port":3000}`),
			mode:      installFuzzJSON,
			operation: 0,
		},
		{
			body: []byte(
				`{"dns_port":53,"interfaces":{"eth0":null},"version":"v0.107.52","web_port":3000}`,
			),
			mode:      installFuzzJSON,
			operation: 0,
		},
		{
			body: []byte(`{
				"dns_port":53,
				"interfaces":{"eth0":{"flags":"up"}},
				"version":"v0.107.52",
				"web_port":3000
			}`),
			mode:      installFuzzJSON,
			operation: 0,
		},
		{
			body:      []byte(`{"dns_port":65536,"interfaces":{},"version":"","web_port":0}`),
			mode:      installFuzzJSON,
			operation: 0,
		},
		{body: []byte(`{"dns_port":`), mode: installFuzzJSON, operation: 0},
		{
			body:      []byte(`{"dns_port":53,"interfaces":{},"version":"","web_port":0}`),
			mode:      installFuzzOpaque,
			operation: 0,
		},
		{body: []byte(`rejected`), mode: installFuzzStatus, operation: 0},
		{body: []byte(`redirect`), mode: installFuzzRedirect, operation: 0},
		{body: []byte(`oversized addresses response`), mode: installFuzzTooLarge, operation: 0},
	})
}

// addInstallCheckResponseFuzzSeeds registers configuration-check fixtures.
func addInstallCheckResponseFuzzSeeds(f *testing.F) {
	f.Helper()

	addInstallFuzzSeeds(f, []installFuzzSeed{
		{body: []byte(installFuzzValidCheckResponse), mode: installFuzzJSON, operation: 1},
		{
			body: []byte(`{
				"dns":{"status":"ready","can_autofix":true},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"yes","ip":"","error":null}
			}`),
			mode:      installFuzzJSON,
			operation: 1,
		},
		{
			body: []byte(`{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"no","ip":"192.0.2.53","error":""}
			}`),
			mode:      installFuzzJSON,
			operation: 1,
		},
		{
			body: []byte(`{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"error","ip":null,"error":"unavailable"}
			}`),
			mode:      installFuzzJSON,
			operation: 1,
		},
		{body: []byte(`null`), mode: installFuzzJSON, operation: 1},
		{body: []byte(`{"dns":{},"web":{},"static_ip":{}}`), mode: installFuzzJSON, operation: 1},
		{
			body: []byte(
				`{"dns":{"status":"","can_autofix":false},"web":{"status":"","can_autofix":false}}`,
			),
			mode:      installFuzzJSON,
			operation: 1,
		},
		{
			body: []byte(`{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"unknown"}
			}`),
			mode:      installFuzzJSON,
			operation: 1,
		},
		{body: []byte(`{"dns":`), mode: installFuzzJSON, operation: 1},
		{body: []byte(installFuzzValidCheckResponse), mode: installFuzzOpaque, operation: 1},
		{body: []byte(`rejected`), mode: installFuzzStatus, operation: 1},
		{body: []byte(`redirect`), mode: installFuzzRedirect, operation: 1},
		{body: []byte(`oversized check response`), mode: installFuzzTooLarge, operation: 1},
	})
}

// addInstallConfigureResponseFuzzSeeds registers body-agnostic configure fixtures.
func addInstallConfigureResponseFuzzSeeds(f *testing.F) {
	f.Helper()

	addInstallFuzzSeeds(f, []installFuzzSeed{
		{body: []byte(`accepted`), mode: installFuzzJSON, operation: 2},
		{body: []byte(`accepted`), mode: installFuzzOpaque, operation: 2},
		{body: []byte(`rejected`), mode: installFuzzStatus, operation: 2},
		{body: []byte(`redirect`), mode: installFuzzRedirect, operation: 2},
		{body: []byte(`oversized configure response`), mode: installFuzzTooLarge, operation: 2},
	})
}

// addInstallFuzzSeeds registers one group of response fixtures.
func addInstallFuzzSeeds(f *testing.F, seeds []installFuzzSeed) {
	f.Helper()

	for _, seed := range seeds {
		f.Add(seed.operation, seed.mode, seed.body)
	}
}

// exerciseInstallResponseFuzz checks one bounded installation response operation.
func exerciseInstallResponseFuzz(t *testing.T, operation, mode byte, body []byte) {
	t.Helper()

	if len(body) > installFuzzMaxResponseBytes {
		return
	}

	state := newInstallFuzzState(t, operation, mode, body)

	switch state.operation.name {
	case operationInstallGetAddresses:
		addresses, err := state.client.InstallGetAddresses(t.Context())
		requireInstallAddressesFuzzResult(t, state, addresses, err)
	case operationInstallCheckConfig:
		result, err := state.client.InstallCheckConfig(t.Context(), CheckConfigRequest{})
		requireInstallCheckFuzzResult(t, state, result, err)
	case operationInstallConfigure:
		err := state.client.InstallConfigure(t.Context(), InitialConfiguration{})
		requireInstallConfigureFuzzResult(t, state, err)
	default:
		require.Fail(t, "unreachable install operation", state.operation.name)
	}

	require.Len(t, state.captures, 1)
	requireInstallCapturedRequest(t, state.operation, state.captures[0])
}

// newInstallFuzzState creates an offline client and deterministic response policy.
func newInstallFuzzState(
	t *testing.T,
	operationSelector byte,
	modeSelector byte,
	body []byte,
) *installFuzzState {
	t.Helper()

	response := bytes.Clone(body)
	mode := modeSelector % (installFuzzTooLarge + 1)
	if mode == installFuzzTooLarge && len(response) < 2 {
		response = []byte("xx")
	}

	limit := max(int64(1), int64(len(response)))
	if mode == installFuzzTooLarge {
		limit = max(int64(1), int64(len(response))/2)
	}

	state := &installFuzzState{
		captures:  make([]fuzzRequestCapture, 0, 2),
		client:    nil,
		limit:     limit,
		mode:      mode,
		operation: selectInstallFuzzOperation(operationSelector),
		response:  response,
	}
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		state.captures = append(state.captures, capture)

		return installFuzzHTTPResponse(request, state), nil
	})

	state.client = newFuzzClient(t, transport, state.limit)

	return state
}

// selectInstallFuzzOperation selects one public installation operation.
func selectInstallFuzzOperation(selector byte) installFuzzOperation {
	switch selector % 3 {
	case 0:
		return installFuzzOperation{
			jsonResponse: true,
			method:       http.MethodGet,
			name:         operationInstallGetAddresses,
			path:         "/api/control/install/get_addresses",
		}
	case 1:
		return installFuzzOperation{
			jsonResponse: true,
			method:       http.MethodPost,
			name:         operationInstallCheckConfig,
			path:         "/api/control/install/check_config",
		}
	default:
		return installFuzzOperation{
			jsonResponse: false,
			method:       http.MethodPost,
			name:         operationInstallConfigure,
			path:         "/api/control/install/configure",
		}
	}
}

// installFuzzHTTPResponse creates the selected deterministic HTTP response.
func installFuzzHTTPResponse(
	request *http.Request,
	state *installFuzzState,
) *http.Response {
	statusCode := http.StatusOK
	contentType := testResponseMediaType

	switch state.mode {
	case installFuzzOpaque:
		contentType = installFuzzTextMediaType
	case installFuzzStatus:
		statusCode = http.StatusUnprocessableEntity
		contentType = installFuzzTextMediaType
	case installFuzzRedirect:
		statusCode = http.StatusTemporaryRedirect
		contentType = installFuzzTextMediaType
	case installFuzzTooLarge, installFuzzJSON:
	default:
		contentType = testResponseMediaType
	}

	response := fuzzHTTPResponse(request, statusCode, contentType, state.response)
	if state.mode == installFuzzRedirect {
		response.Header.Set("Location", installFuzzRedirectLocation)
	}

	return response
}

// requireInstallCapturedRequest verifies one captured installation request.
func requireInstallCapturedRequest(
	t *testing.T,
	operation installFuzzOperation,
	capture fuzzRequestCapture,
) {
	t.Helper()

	assert.Equal(t, operation.method, capture.method)
	assert.Equal(t, operation.path, capture.path)
	assert.Empty(t, capture.query)

	if operation.method == http.MethodGet {
		assert.Empty(t, capture.contentType)
		assert.Empty(t, capture.body)

		return
	}

	assert.Equal(t, testResponseMediaType, capture.contentType)
	assert.NotEmpty(t, capture.body)
	requireFuzzJSONBody(t, capture)
}

// requireInstallAddressesFuzzResult verifies address success invariants or structured failure.
func requireInstallAddressesFuzzResult(
	t *testing.T,
	state *installFuzzState,
	addresses *AddressesInfo,
	err error,
) {
	t.Helper()

	if err == nil {
		require.NotNil(t, addresses)
		assert.NotNil(t, addresses.Interfaces)

		for name, networkInterface := range addresses.Interfaces {
			assert.NotNil(t, networkInterface.IPv4Addresses, "interface %q IPv4 addresses", name)
			assert.NotNil(t, networkInterface.IPv6Addresses, "interface %q IPv6 addresses", name)
		}
	} else {
		assert.Nil(t, addresses)
	}

	requireInstallFuzzOutcome(t, state, err)
}

// requireInstallCheckFuzzResult verifies check success or structured failure.
func requireInstallCheckFuzzResult(
	t *testing.T,
	state *installFuzzState,
	result *CheckConfigResponse,
	err error,
) {
	t.Helper()

	if err == nil {
		require.NotNil(t, result)
	} else {
		assert.Nil(t, result)
	}

	requireInstallFuzzOutcome(t, state, err)
}

// requireInstallConfigureFuzzResult verifies body-agnostic configure outcomes.
func requireInstallConfigureFuzzResult(t *testing.T, state *installFuzzState, err error) {
	t.Helper()
	requireInstallFuzzOutcome(t, state, err)
}

// requireInstallFuzzOutcome verifies the structured error for the selected response mode.
func requireInstallFuzzOutcome(t *testing.T, state *installFuzzState, err error) {
	t.Helper()

	if err == nil {
		requireInstallFuzzSuccess(t, state)

		return
	}
	if state.mode == installFuzzOpaque && !state.operation.jsonResponse {
		require.NoError(t, err)

		return
	}

	clientErr := requireFuzzError(
		t,
		err,
		installFuzzErrorKind(state),
		state.operation.name,
		state.operation.method,
	)
	requireInstallFuzzMetadata(t, state, clientErr)
}

// requireInstallFuzzSuccess verifies the successful mode for one response policy.
func requireInstallFuzzSuccess(t *testing.T, state *installFuzzState) {
	t.Helper()

	if state.operation.jsonResponse {
		assert.Equal(t, installFuzzJSON, state.mode)

		return
	}

	assert.Contains(t, []byte{installFuzzJSON, installFuzzOpaque}, state.mode)
}

// installFuzzErrorKind classifies the expected error for one response policy.
func installFuzzErrorKind(state *installFuzzState) ErrorKind {
	switch state.mode {
	case installFuzzOpaque:
		return ErrorKindContentType
	case installFuzzStatus:
		return ErrorKindStatus
	case installFuzzRedirect:
		return ErrorKindRedirect
	case installFuzzTooLarge:
		return ErrorKindResponseTooLarge
	case installFuzzJSON:
		return ErrorKindJSON
	default:
		return ""
	}
}

// requireInstallFuzzMetadata verifies mode-specific structured error fields.
func requireInstallFuzzMetadata(t *testing.T, state *installFuzzState, clientErr *Error) {
	t.Helper()

	switch state.mode {
	case installFuzzStatus:
		assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
		assert.Equal(t, state.response, clientErr.Body)
		assert.Equal(t, installFuzzTextMediaType, clientErr.ContentType)
	case installFuzzRedirect:
		assert.Equal(t, installFuzzRedirectLocation, clientErr.Location)
	case installFuzzTooLarge:
		assert.Equal(t, state.limit, clientErr.Limit)
		assert.Equal(t, http.StatusOK, clientErr.StatusCode)
		assert.Equal(t, testResponseMediaType, clientErr.ContentType)
	default:
		require.Error(t, clientErr.Err)
	}
}

// exerciseInstallRequestFuzz checks request presence and values for both POST operations.
func exerciseInstallRequestFuzz(t *testing.T, data []byte) {
	t.Helper()

	if len(data) > installFuzzMaxRequestBytes || !utf8.Valid(data) {
		return
	}

	checkRequest := buildInstallCheckFuzzRequest(data)
	configuration := buildInstallConfigurationFuzz(data)
	state := newInstallFuzzState(t, 1, installFuzzJSON, []byte(installFuzzValidCheckResponse))

	result, err := state.client.InstallCheckConfig(t.Context(), checkRequest)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NoError(t, state.client.InstallConfigure(t.Context(), configuration))
	require.Len(t, state.captures, 2)

	checkOperation := selectInstallFuzzOperation(1)
	configureOperation := selectInstallFuzzOperation(2)

	requireInstallCapturedRequest(t, checkOperation, state.captures[0])
	requireInstallCapturedRequest(t, configureOperation, state.captures[1])
	requireInstallCheckRequestJSON(t, state.captures[0], checkRequest)
	requireInstallConfigurationJSON(t, state.captures[1], configuration)
}

// buildInstallCheckFuzzRequest builds a presence-sensitive configuration check request.
func buildInstallCheckFuzzRequest(data []byte) CheckConfigRequest {
	request := CheckConfigRequest{}
	if installFuzzControlBit(data, 0) {
		request.DNS = buildInstallRequestInfoFuzz(data)
	}
	if installFuzzControlBit(data, 1) {
		request.Web = buildInstallRequestInfoFuzz(data)
	}
	if installFuzzControlBit(data, 2) {
		request.SetStaticIP = new(installFuzzControlBit(data, 6))
	}

	return request
}

// buildInstallRequestInfoFuzz builds one presence-sensitive listener request.
func buildInstallRequestInfoFuzz(data []byte) *CheckConfigRequestInfo {
	info := &CheckConfigRequestInfo{}
	if installFuzzControlBit(data, 3) {
		info.IP = new(string(data))
	}
	if installFuzzControlBit(data, 4) {
		port := uint16(0)
		if len(data) > 3 {
			port = uint16(data[3])
		}

		info.Port = &port
	}
	if installFuzzControlBit(data, 5) {
		info.Autofix = new(installFuzzControlBit(data, 7))
	}

	return info
}

// buildInstallConfigurationFuzz builds a fully present initial configuration.
func buildInstallConfigurationFuzz(data []byte) InitialConfiguration {
	value := string(data)
	dnsPort := uint16(0)
	webPort := uint16(0)
	if len(data) > 3 {
		dnsPort = uint16(data[3])
	}
	if len(data) > 4 {
		webPort = uint16(data[4])
	}

	return InitialConfiguration{
		DNS:      AddressInfo{IP: value, Port: dnsPort},
		Web:      AddressInfo{IP: value, Port: webPort},
		Username: value,
		Password: value,
	}
}

// installFuzzControlBit reports whether the bounded control byte contains a bit.
func installFuzzControlBit(data []byte, bit int) bool {
	return len(data) > 0 && data[0]&(1<<bit) != 0
}

// requireInstallCheckRequestJSON verifies exact optional check-request presence and values.
func requireInstallCheckRequestJSON(
	t *testing.T,
	capture fuzzRequestCapture,
	request CheckConfigRequest,
) {
	t.Helper()

	var fields map[string]any

	require.NoError(t, json.Unmarshal(capture.body, &fields))
	requireInstallFuzzFields(t, fields, map[string]bool{
		"dns":           request.DNS != nil,
		"web":           request.Web != nil,
		"set_static_ip": request.SetStaticIP != nil,
	})

	if request.SetStaticIP != nil {
		assert.Equal(t, *request.SetStaticIP, fields["set_static_ip"])
	}

	requireInstallInfoJSON(t, fields, "dns", request.DNS)
	requireInstallInfoJSON(t, fields, "web", request.Web)
}

// requireInstallInfoJSON verifies one optional listener request object.
func requireInstallInfoJSON(
	t *testing.T,
	fields map[string]any,
	name string,
	info *CheckConfigRequestInfo,
) {
	t.Helper()

	if info == nil {
		return
	}

	listenerFields, ok := fields[name].(map[string]any)
	require.True(t, ok)
	requireInstallFuzzFields(t, listenerFields, map[string]bool{
		"ip":      info.IP != nil,
		"port":    info.Port != nil,
		"autofix": info.Autofix != nil,
	})

	if info.IP != nil {
		assert.Equal(t, *info.IP, listenerFields["ip"])
	}
	if info.Port != nil {
		assert.InDelta(t, float64(*info.Port), listenerFields["port"], 0)
	}
	if info.Autofix != nil {
		assert.Equal(t, *info.Autofix, listenerFields["autofix"])
	}
}

// requireInstallConfigurationJSON verifies all required configuration fields and values.
func requireInstallConfigurationJSON(
	t *testing.T,
	capture fuzzRequestCapture,
	configuration InitialConfiguration,
) {
	t.Helper()

	var fields map[string]any

	require.NoError(t, json.Unmarshal(capture.body, &fields))
	requireInstallFuzzFields(t, fields, map[string]bool{
		"dns":      true,
		"web":      true,
		"username": true,
		"password": true,
	})
	assert.Equal(t, configuration.Username, fields["username"])
	assert.Equal(t, configuration.Password, fields["password"])
	requireInstallAddressJSON(t, fields, "dns", configuration.DNS)
	requireInstallAddressJSON(t, fields, "web", configuration.Web)
}

// requireInstallAddressJSON verifies one required listener address object.
func requireInstallAddressJSON(
	t *testing.T,
	fields map[string]any,
	name string,
	address AddressInfo,
) {
	t.Helper()

	addressFields, ok := fields[name].(map[string]any)
	require.True(t, ok)
	requireInstallFuzzFields(t, addressFields, map[string]bool{"ip": true, "port": true})
	assert.Equal(t, address.IP, addressFields["ip"])
	assert.InDelta(t, float64(address.Port), addressFields["port"], 0)
}

// requireInstallFuzzFields verifies exact key presence in one JSON object.
func requireInstallFuzzFields(
	t *testing.T,
	fields map[string]any,
	expected map[string]bool,
) {
	t.Helper()

	expectedCount := 0

	for key, present := range expected {
		if present {
			expectedCount++
		}

		_, actual := fields[key]
		require.Equal(t, present, actual, "JSON field %q presence", key)
	}

	require.Len(t, fields, expectedCount)
}
