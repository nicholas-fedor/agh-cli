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

// installIntegrationCheckConfigPresenceCase describes one optional response presence case.
type installIntegrationCheckConfigPresenceCase struct {
	name       string
	body       string
	wantStatic *adguard.CheckConfigStaticIPStatus
	wantIP     *string
	wantError  *string
}

// installIntegrationOperation describes one concrete installation request.
type installIntegrationOperation struct {
	name      string
	method    string
	path      string
	operation string
	invoke    func(context.Context, *adguard.Client) error
}

// Installation integration tests use fixed wire settings and representative payloads.
const (
	installIntegrationGetAddressesPath = "/control/install/get_addresses"
	installIntegrationCheckConfigPath  = "/control/install/check_config"
	installIntegrationConfigurePath    = "/control/install/configure"
	installIntegrationRedirectPath     = "/complete/install"
	installIntegrationUsername         = "install-integration-user"
	installIntegrationPassword         = "install-integration-password"
	installIntegrationUserAgent        = "adguard-install-integration-test/1.0"
	installIntegrationTextMediaType    = "text/plain; charset=utf-8"
	// AdguardIntegrationConfigureName is the shared configure operation case name.
	adguardIntegrationConfigureName   = "configure"
	installIntegrationResponseLimit   = int64(4096)
	installIntegrationCancellationTTL = time.Second
	installIntegrationAddressesJSON   = `{
		"dns_port": 53,
		"interfaces": {
			"eth0": {
				"flags": "up|broadcast|running|multicast",
				"gateway_ip": "192.0.2.1",
				"hardware_address": "00:11:22:33:44:55",
				"ipv4_addresses": ["192.0.2.10"],
				"ipv6_addresses": ["2001:db8::10"],
				"name": "eth0"
			},
			"lo": {
				"flags": "up|loopback|running",
				"gateway_ip": "",
				"hardware_address": "00:00:00:00:00:00",
				"ipv4_addresses": ["127.0.0.1"],
				"ipv6_addresses": ["::1"],
				"name": "lo"
			}
		},
		"version": "v0.107.52",
		"web_port": 3000,
		"future_member": true
	}`
	installIntegrationCheckConfigJSON = `{
		"dns": {"status": "ok", "can_autofix": false},
		"web": {"status": "ok", "can_autofix": false},
		"static_ip": {}
	}`
)

// installIntegrationCheckConfigPresenceCases returns optional static-IP presence cases.
//
// Returns:
//   - The omitted, null, explicit-empty, and error-state response cases.
func installIntegrationCheckConfigPresenceCases() []installIntegrationCheckConfigPresenceCase {
	staticYes := adguard.CheckConfigStaticIPYes
	staticError := adguard.CheckConfigStaticIPError
	emptyIP := ""
	emptyError := ""
	errorIP := "192.0.2.53"
	errorMessage := "default route unavailable"

	return []installIntegrationCheckConfigPresenceCase{
		{
			name: "omitted optional fields",
			body: `{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{}
			}`,
		},
		{
			name: "null optional fields",
			body: `{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":null,"ip":null,"error":null}
			}`,
		},
		{
			name: "explicit empty values",
			body: `{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"yes","ip":"","error":""}
			}`,
			wantStatic: &staticYes,
			wantIP:     &emptyIP,
			wantError:  &emptyError,
		},
		{
			name: "error state",
			body: `{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"error","ip":"192.0.2.53","error":"default route unavailable"}
			}`,
			wantStatic: &staticError,
			wantIP:     &errorIP,
			wantError:  &errorMessage,
		},
	}
}

// TestInstallIntegrationGetAddressesDecodesJSON verifies the exact authenticated GET and typed response.
func TestInstallIntegrationGetAddressesDecodesJSON(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertInstallIntegrationRequest(t, r, http.MethodGet, installIntegrationGetAddressesPath)

		w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType+"; charset=utf-8")
		writeInstallIntegrationBody(w, installIntegrationAddressesJSON)
	}))
	client := newInstallIntegrationClient(
		t,
		server,
		adguard.WithMaxResponseBodySize(int64(len(installIntegrationAddressesJSON))),
	)

	addresses, err := client.InstallGetAddresses(t.Context())

	require.NoError(t, err)
	assert.Equal(t, &adguard.AddressesInfo{
		DNSPort: 53,
		Interfaces: map[string]adguard.NetInterface{
			"eth0": {
				Flags:           "up|broadcast|running|multicast",
				GatewayIP:       adguardIntegrationGatewayIP,
				HardwareAddress: "00:11:22:33:44:55",
				IPv4Addresses:   []string{clientsIntegrationDeskID},
				IPv6Addresses:   []string{"2001:db8::10"},
				Name:            "eth0",
			},
			"lo": {
				Flags:           "up|loopback|running",
				GatewayIP:       "",
				HardwareAddress: "00:00:00:00:00:00",
				IPv4Addresses:   []string{"127.0.0.1"},
				IPv6Addresses:   []string{"::1"},
				Name:            "lo",
			},
		},
		Version: "v0.107.52",
		WebPort: 3000,
	}, addresses)
}

// TestInstallIntegrationGetAddressesAcceptsRequiredZeroValues verifies required JSON
// presence without value constraints.
func TestInstallIntegrationGetAddressesAcceptsRequiredZeroValues(t *testing.T) {
	t.Parallel()

	const responseBody = `{"dns_port":0,"interfaces":{},"version":"","web_port":0}`

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertInstallIntegrationRequest(t, r, http.MethodGet, installIntegrationGetAddressesPath)

		w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
		writeInstallIntegrationBody(w, responseBody)
	}))
	client := newInstallIntegrationClient(t, server)

	addresses, err := client.InstallGetAddresses(t.Context())

	require.NoError(t, err)
	assert.Equal(t, &adguard.AddressesInfo{
		DNSPort:    0,
		Interfaces: map[string]adguard.NetInterface{},
		Version:    "",
		WebPort:    0,
	}, addresses)
}

// TestInstallIntegrationGetAddressesRejectsMalformedResponses verifies strict JSON and required-field errors.
func TestInstallIntegrationGetAddressesRejectsMalformedResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: safetyIntegrationMalformedName, body: `{"dns_port":`},
		{name: "null response", body: safetyIntegrationNullName},
		{name: "missing top-level field", body: `{"interfaces":{},"version":"","web_port":0}`},
		{
			name: "null interface",
			body: `{"dns_port":0,"interfaces":{"eth0":null},"version":"","web_port":0}`,
		},
		{
			name: "missing interface field",
			body: `{
				"dns_port":0,
				"interfaces":{
					"eth0":{
						"flags":"up",
						"gateway_ip":"",
						"hardware_address":"",
						"ipv4_addresses":[],
						"ipv6_addresses":[]
					}
				},
				"version":"",
				"web_port":0
			}`,
		},
		{
			name: "wrong field type",
			body: `{"dns_port":"53","interfaces":{},"version":"","web_port":0}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, http.MethodGet, installIntegrationGetAddressesPath)

				w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
				writeInstallIntegrationBody(w, test.body)
			}))
			client := newInstallIntegrationClient(t, server)

			addresses, err := client.InstallGetAddresses(t.Context())

			assert.Nil(t, addresses)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindJSON)
			assert.Equal(t, "install_get_addresses", clientErr.Operation)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Zero(t, clientErr.StatusCode)
		})
	}
}

// TestInstallIntegrationCheckConfigPreservesRequestPresence verifies omitted and explicit zero-valued fields.
func TestInstallIntegrationCheckConfigPreservesRequestPresence(t *testing.T) {
	t.Parallel()

	emptyIP := ""
	zeroPort := uint16(0)
	disabled := false

	tests := []struct {
		name     string
		request  adguard.CheckConfigRequest
		wantBody string
	}{
		{
			name:     "all optional fields omitted",
			request:  adguard.CheckConfigRequest{},
			wantBody: `{}`,
		},
		{
			name: "explicit empty zero and false",
			request: adguard.CheckConfigRequest{
				DNS: &adguard.CheckConfigRequestInfo{
					IP:      &emptyIP,
					Port:    &zeroPort,
					Autofix: &disabled,
				},
				Web:         &adguard.CheckConfigRequestInfo{},
				SetStaticIP: &disabled,
			},
			wantBody: `{
				"dns":{"ip":"","port":0,"autofix":false},
				"web":{},
				"set_static_ip":false
			}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, http.MethodPost, installIntegrationCheckConfigPath)

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.JSONEq(t, test.wantBody, string(body))

				w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
				writeInstallIntegrationBody(w, installIntegrationCheckConfigJSON)
			}))
			client := newInstallIntegrationClient(t, server)

			result, err := client.InstallCheckConfig(t.Context(), test.request)

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, adguard.CheckConfigResponseInfo{Status: "ok", CanAutofix: false}, result.DNS)
			assert.Equal(t, adguard.CheckConfigResponseInfo{Status: "ok", CanAutofix: false}, result.Web)
			assert.Nil(t, result.StaticIP.Static)
			assert.Nil(t, result.StaticIP.IP)
			assert.Nil(t, result.StaticIP.Error)
		})
	}
}

// TestInstallIntegrationCheckConfigDecodesOptionalResponsePresence verifies absent, null, and explicit optional values.
func TestInstallIntegrationCheckConfigDecodesOptionalResponsePresence(t *testing.T) {
	t.Parallel()

	tests := installIntegrationCheckConfigPresenceCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, http.MethodPost, installIntegrationCheckConfigPath)

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.JSONEq(t, `{}`, string(body))

				w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
				writeInstallIntegrationBody(w, test.body)
			}))
			client := newInstallIntegrationClient(t, server)

			result, err := client.InstallCheckConfig(t.Context(), adguard.CheckConfigRequest{})

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, test.wantStatic, result.StaticIP.Static)
			assert.Equal(t, test.wantIP, result.StaticIP.IP)
			assert.Equal(t, test.wantError, result.StaticIP.Error)
		})
	}
}

// TestInstallIntegrationCheckConfigRejectsMalformedResponses verifies response schema and enum failures.
func TestInstallIntegrationCheckConfigRejectsMalformedResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "malformed JSON", body: `{"dns":`},
		{name: "null response", body: safetyIntegrationNullName},
		{
			name: "missing DNS member",
			body: `{"web":{"status":"","can_autofix":false},"static_ip":{}}`,
		},
		{
			name: "missing static IP member",
			body: `{"dns":{"status":"","can_autofix":false},"web":{"status":"","can_autofix":false}}`,
		},
		{
			name: "missing required listener field",
			body: `{
				"dns":{"status":""},
				"web":{"status":"","can_autofix":false},
				"static_ip":{}
			}`,
		},
		{
			name: "invalid static IP state",
			body: `{
				"dns":{"status":"","can_autofix":false},
				"web":{"status":"","can_autofix":false},
				"static_ip":{"static":"unknown"}
			}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, http.MethodPost, installIntegrationCheckConfigPath)

				w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
				writeInstallIntegrationBody(w, test.body)
			}))
			client := newInstallIntegrationClient(t, server)

			result, err := client.InstallCheckConfig(t.Context(), adguard.CheckConfigRequest{})

			assert.Nil(t, result)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindJSON)
			assert.Equal(t, "install_check_config", clientErr.Operation)
			assert.Equal(t, http.MethodPost, clientErr.Method)
			assert.Zero(t, clientErr.StatusCode)
		})
	}
}

// TestInstallIntegrationConfigurePreservesRequiredFields verifies every configuration member reaches the wire.
func TestInstallIntegrationConfigurePreservesRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		configuration adguard.InitialConfiguration
		wantBody      string
		statusCode    int
		contentType   string
		responseBody  string
	}{
		{
			name: "populated configuration",
			configuration: adguard.InitialConfiguration{
				DNS:      adguard.AddressInfo{IP: "192.0.2.53", Port: 53},
				Web:      adguard.AddressInfo{IP: "192.0.2.2", Port: 3000},
				Username: adguardIntegrationAdminName,
				Password: "password123",
			},
			wantBody: `{
				"dns":{"ip":"192.0.2.53","port":53},
				"web":{"ip":"192.0.2.2","port":3000},
				"username":"admin",
				"password":"password123"
			}`,
			statusCode:   http.StatusOK,
			contentType:  installIntegrationTextMediaType,
			responseBody: "configuration accepted",
		},
		{
			name:          "zero configuration",
			configuration: adguard.InitialConfiguration{},
			wantBody: `{
				"dns":{"ip":"","port":0},
				"web":{"ip":"","port":0},
				"username":"",
				"password":""
			}`,
			statusCode: http.StatusNoContent,
		},
	}

	for index := range tests {
		test := &tests[index]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, http.MethodPost, installIntegrationConfigurePath)

				body, err := io.ReadAll(r.Body)
				assert.NoError(t, err)
				assert.JSONEq(t, test.wantBody, string(body))

				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.statusCode)

				_, err = io.WriteString(w, test.responseBody)
				assert.NoError(t, err)
			}))
			client := newInstallIntegrationClient(t, server)

			err := client.InstallConfigure(t.Context(), test.configuration)

			require.NoError(t, err)
		})
	}
}

// TestInstallIntegrationRejectsMalformedInput verifies request encoding failures occur before transport.
func TestInstallIntegrationRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation string
		method    string
		invoke    func(*adguard.Client) error
	}{
		{
			name:      "check configuration",
			operation: "install_check_config",
			method:    http.MethodPost,
			invoke: func(client *adguard.Client) error {
				invalidIP := string([]byte{0xff})
				_, err := client.InstallCheckConfig(t.Context(), adguard.CheckConfigRequest{
					DNS: &adguard.CheckConfigRequestInfo{IP: &invalidIP},
				})

				return err
			},
		},
		{
			name:      adguardIntegrationConfigureName,
			operation: "install_configure",
			method:    http.MethodPost,
			invoke: func(client *adguard.Client) error {
				return client.InstallConfigure(t.Context(), adguard.InitialConfiguration{
					Username: string([]byte{0xff}),
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			client := newInstallIntegrationClient(t, server)

			err := test.invoke(client)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			require.ErrorContains(t, err, "encode request")
			assert.Zero(t, requests.Load())
		})
	}
}

// TestInstallIntegrationReturnsStructuredContentTypeErrors verifies JSON operations reject opaque success media types.
func TestInstallIntegrationReturnsStructuredContentTypeErrors(t *testing.T) {
	t.Parallel()

	operations := installIntegrationOperations()
	for _, operation := range operations[:2] {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, operation.method, operation.path)

				w.Header().Set("Content-Type", installIntegrationTextMediaType)
				w.WriteHeader(http.StatusOK)
				writeInstallIntegrationBody(w, `{"unexpected":true}`)
			}))
			client := newInstallIntegrationClient(t, server)

			err := operation.invoke(t.Context(), client)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindContentType)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
			assert.Equal(t, installIntegrationTextMediaType, clientErr.ContentType)
			assert.Empty(t, clientErr.Body)
		})
	}
}

// TestInstallIntegrationReturnsStructuredStatusErrors verifies all operations retain bounded status details.
func TestInstallIntegrationReturnsStructuredStatusErrors(t *testing.T) {
	t.Parallel()

	const responseBody = `{"message":"installation unavailable"}`

	for _, operation := range installIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, operation.method, operation.path)

				w.Header().Set("Content-Type", blockedServicesIntegrationProblemContentType)
				w.WriteHeader(http.StatusServiceUnavailable)
				writeInstallIntegrationBody(w, responseBody)
			}))
			client := newInstallIntegrationClient(t, server)

			err := operation.invoke(t.Context(), client)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindStatus)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.Equal(t, http.StatusServiceUnavailable, clientErr.StatusCode)
			assert.Equal(t, statusIntegrationUnavailableStatus, clientErr.Status)
			assert.Equal(t, blockedServicesIntegrationProblemContentType, clientErr.ContentType)
			assert.JSONEq(t, responseBody, string(clientErr.Body))
		})
	}
}

// TestInstallIntegrationEnforcesResponseLimits verifies all empty and JSON response modes remain bounded.
func TestInstallIntegrationEnforcesResponseLimits(t *testing.T) {
	t.Parallel()

	for _, operation := range installIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, operation.method, operation.path)

				w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
				writeInstallIntegrationBody(w, strings.Repeat("x", 32))
			}))
			client := newInstallIntegrationClient(t, server, adguard.WithMaxResponseBodySize(8))

			err := operation.invoke(t.Context(), client)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
			assert.Equal(t, int64(8), clientErr.Limit)
			assert.Empty(t, clientErr.Body)
		})
	}
}

// TestInstallIntegrationHonorsCancellation verifies in-flight cancellation remains matchable.
func TestInstallIntegrationHonorsCancellation(t *testing.T) {
	t.Parallel()

	for _, operation := range installIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			requestStarted := make(chan struct{})
			releaseHandler := make(chan struct{})
			server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				assertInstallIntegrationRequest(t, r, operation.method, operation.path)
				close(requestStarted)
				<-releaseHandler
			}))
			client := newInstallIntegrationClient(t, server)
			ctx, cancel := context.WithCancel(t.Context())

			defer cancel()
			defer close(releaseHandler)

			result := make(chan error, 1)

			go func() {
				result <- operation.invoke(ctx, client)
			}()

			waitForInstallIntegrationRequest(t, requestStarted)
			cancel()

			err := waitForInstallIntegrationResult(t, result)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

// waitForInstallIntegrationRequest waits for the test server to receive a request.
//
// Parameters:
//   - requestStarted: The channel closed when the handler receives a request.
func waitForInstallIntegrationRequest(t *testing.T, requestStarted <-chan struct{}) {
	t.Helper()

	select {
	case <-requestStarted:
	case <-time.After(installIntegrationCancellationTTL):
		t.Fatal("installation request did not reach the test server")
	}
}

// waitForInstallIntegrationResult waits for a canceled client call to return.
//
// Parameters:
//   - result: The channel receiving the client call result.
//
// Returns:
//   - The error returned by the canceled client call.
func waitForInstallIntegrationResult(t *testing.T, result <-chan error) error {
	t.Helper()

	var err error

	select {
	case err = <-result:
	case <-time.After(installIntegrationCancellationTTL):
		t.Fatal("installation request did not return after cancellation")
	}

	return err
}

// TestInstallIntegrationRejectsRedirects verifies installation credentials are never forwarded.
func TestInstallIntegrationRejectsRedirects(t *testing.T) {
	t.Parallel()

	for _, operation := range installIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			var redirectedRequests atomic.Int32

			server := newInstallIntegrationRedirectServer(t, operation, &redirectedRequests)
			client := newInstallIntegrationClient(t, server)

			err := operation.invoke(t.Context(), client)

			clientErr := requireInstallIntegrationError(t, err, adguard.ErrorKindRedirect)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.Equal(t, localTestServerURL+installIntegrationRedirectPath, clientErr.Location)
			assert.Zero(t, redirectedRequests.Load())
		})
	}
}

// newInstallIntegrationRedirectServer creates a server that rejects and counts redirect attempts.
//
// Parameters:
//   - operation: The original installation request contract.
//   - redirectedRequests: The counter incremented if the redirect target is reached.
//
// Returns:
//   - The configured HTTP test server.
func newInstallIntegrationRedirectServer(
	t *testing.T,
	operation installIntegrationOperation,
	redirectedRequests *atomic.Int32,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == installIntegrationRedirectPath {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		assertInstallIntegrationRequest(t, r, operation.method, operation.path)

		w.Header().Set("Location", installIntegrationRedirectPath)
		w.WriteHeader(http.StatusFound)
	}))
}

// installIntegrationOperations returns the concrete operations covered by transport tests.
//
// Returns:
//   - The get-addresses, check-configuration, and configure operations.
func installIntegrationOperations() []installIntegrationOperation {
	return []installIntegrationOperation{
		{
			name:      "get addresses",
			method:    http.MethodGet,
			path:      installIntegrationGetAddressesPath,
			operation: "install_get_addresses",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.InstallGetAddresses(ctx)

				return err
			},
		},
		{
			name:      "check configuration",
			method:    http.MethodPost,
			path:      installIntegrationCheckConfigPath,
			operation: "install_check_config",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.InstallCheckConfig(ctx, adguard.CheckConfigRequest{})

				return err
			},
		},
		{
			name:      adguardIntegrationConfigureName,
			method:    http.MethodPost,
			path:      installIntegrationConfigurePath,
			operation: "install_configure",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.InstallConfigure(ctx, adguard.InitialConfiguration{})
			},
		},
	}
}

// newInstallIntegrationClient creates a concrete authenticated client for a test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - options: Additional client options applied after the integration defaults.
//
// Returns:
//   - The configured AdGuard client.
func newInstallIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	options ...adguard.Option,
) *adguard.Client {
	t.Helper()

	allOptions := make([]adguard.Option, 0, 4+len(options))

	allOptions = append(
		allOptions,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(installIntegrationUsername, installIntegrationPassword),
		adguard.WithUserAgent(installIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(installIntegrationResponseLimit),
	)
	allOptions = append(allOptions, options...)

	client, err := adguard.NewClient(localTestServerURL, allOptions...)
	require.NoError(t, err)

	return client
}

// assertInstallIntegrationRequest verifies the exact authenticated request metadata.
//
// Parameters:
//   - request: The request received by the test server.
//   - method: The expected HTTP method.
//   - path: The expected request path.
func assertInstallIntegrationRequest(t *testing.T, request *http.Request, method, path string) {
	t.Helper()

	username, password, authenticated := request.BasicAuth()
	assert.True(t, authenticated)
	assert.Equal(t, installIntegrationUsername, username)
	assert.Equal(t, installIntegrationPassword, password)
	assert.Equal(t, method, request.Method)
	assert.Equal(t, path, request.URL.Path)
	assert.Empty(t, request.URL.RawQuery)
	assert.Equal(t, "application/json", request.Header.Get("Accept"))
	assert.Equal(t, installIntegrationUserAgent, request.Header.Get("User-Agent"))

	if method == http.MethodGet {
		assert.Zero(t, request.ContentLength)
		assert.Empty(t, request.Header.Get("Content-Type"))

		return
	}

	assert.Positive(t, request.ContentLength)
	assert.Equal(t, "application/json", request.Header.Get("Content-Type"))
}

// requireInstallIntegrationError extracts and verifies a structured installation error.
//
// Parameters:
//   - err: The error returned by an installation operation.
//   - kind: The expected structured error kind.
//
// Returns:
//   - The extracted structured client error.
func requireInstallIntegrationError(
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

// writeInstallIntegrationBody writes a response body while tolerating client disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeInstallIntegrationBody(w http.ResponseWriter, body string) {
	_, err := io.WriteString(w, body)
	if err != nil {
		return
	}
}
