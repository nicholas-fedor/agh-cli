// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// InstallTestPathGetAddresses is the address-listing request path.
	installTestPathGetAddresses = "/control/install/get_addresses"
	// InstallTestPathCheckConfig is the configuration-check request path.
	installTestPathCheckConfig = "/control/install/check_config"
	// InstallTestPathConfigure is the initial-configuration request path.
	installTestPathConfigure = "/control/install/configure"
	// InstallTestOperationGet is the structured name of the address-listing operation.
	installTestOperationGet = "install_get_addresses"
	// InstallTestOperationCheck is the structured name of the configuration-check operation.
	installTestOperationCheck = "install_check_config"
	// InstallTestOperationApply is the structured name of the initial-configuration operation.
	installTestOperationApply = "install_configure"
	// InstallTestUsername is the Basic authentication username for installation fixtures.
	installTestUsername = "install-user"
	// InstallTestPassword is the Basic authentication password for installation fixtures.
	installTestPassword = "install-password"
	// InstallTestUserAgent is the expected client User-Agent for installation fixtures.
	installTestUserAgent = "adguard-install-test/1.0"
	// InstallTestServerURL is the base URL routed by the in-memory transport.
	installTestServerURL = "http://127.0.0.1"
)

// TestInstallServiceIsImplemented verifies the concrete client satisfies the
// public installation service contract.
func TestInstallServiceIsImplemented(t *testing.T) {
	t.Parallel()

	client, err := NewClient("http://127.0.0.1")
	require.NoError(t, err)

	var service InstallService = client

	assert.NotNil(t, service)
}

// TestInstallGetAddresses verifies the pinned GET request and JSON response.
func TestInstallGetAddresses(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, installTestUsername, username)
		assert.Equal(t, installTestPassword, password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, installTestPathGetAddresses, r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Zero(t, r.ContentLength)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, installTestUserAgent, r.Header.Get("User-Agent"))
		assert.Empty(t, r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Empty(t, body)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		_, err = io.WriteString(w, `{
			"dns_port": 53,
			"interfaces": {
				"eth0": {
					"flags": "up|broadcast|running",
					"gateway_ip": "192.0.2.1",
					"hardware_address": "00:11:22:33:44:55",
					"ipv4_addresses": ["192.0.2.10"],
					"ipv6_addresses": ["2001:db8::10"],
					"name": "eth0"
				}
			},
			"version": "v0.107.0",
			"web_port": 3000,
			"future_member": true
		}`)
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 4096)

	result, err := client.InstallGetAddresses(t.Context())

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, uint16(53), result.DNSPort)
	assert.Equal(t, uint16(3000), result.WebPort)
	assert.Equal(t, "v0.107.0", result.Version)
	require.Contains(t, result.Interfaces, "eth0")
	assert.Equal(t, NetInterface{
		Flags:           "up|broadcast|running",
		GatewayIP:       "192.0.2.1",
		HardwareAddress: "00:11:22:33:44:55",
		IPv4Addresses:   []string{"192.0.2.10"},
		IPv6Addresses:   []string{"2001:db8::10"},
		Name:            "eth0",
	}, result.Interfaces["eth0"])
}

// TestInstallGetAddressesRejectsMissingRequiredField verifies required response
// members are not silently replaced by zero values.
func TestInstallGetAddressesRejectsMissingRequiredField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing interfaces",
			body: `{"dns_port":53,"version":"v0.107.0","web_port":3000}`,
		},
		{
			name: "null interface",
			body: `{"dns_port":53,"interfaces":{"eth0":null},"version":"v0.107.0","web_port":3000}`,
		},
		{
			name: "missing interface address",
			body: `{"dns_port":53,"interfaces":{"eth0":` +
				`{"flags":"up","gateway_ip":"192.0.2.1","hardware_address":"00:11",` +
				`"ipv4_addresses":[],"name":"eth0"}},` +
				`"version":"v0.107.0","web_port":3000}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				_, err := io.WriteString(w, test.body)
				assert.NoError(t, err)
			}))
			client := newInstallTestClient(t, server, 4096)

			result, err := client.InstallGetAddresses(t.Context())

			assert.Nil(t, result)

			clientErr := requireInstallError(t, err, ErrorKindJSON)
			assert.Equal(t, installTestOperationGet, clientErr.Operation)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestInstallGetAddressesReturnsStatusError verifies structured non-success
// response details.
func TestInstallGetAddressesReturnsStatusError(t *testing.T) {
	t.Parallel()

	const responseBody = `{"message":"unable to enumerate interfaces"}`

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 4096)

	result, err := client.InstallGetAddresses(t.Context())

	assert.Nil(t, result)

	clientErr := requireInstallError(t, err, ErrorKindStatus)
	assert.Equal(t, installTestOperationGet, clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusInternalServerError, clientErr.StatusCode)
	assert.Equal(t, "500 Internal Server Error", clientErr.Status)
	assert.Equal(t, "application/json", clientErr.ContentType)
	assert.JSONEq(t, responseBody, string(clientErr.Body))
}

// TestInstallGetAddressesEnforcesResponseLimit verifies the JSON response is
// bounded before decoding.
func TestInstallGetAddressesEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		_, err := io.WriteString(w, `{"dns_port":53,"interfaces":{},"version":"v0.107.0","web_port":3000}`)
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 8)

	result, err := client.InstallGetAddresses(t.Context())

	assert.Nil(t, result)

	clientErr := requireInstallError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, installTestOperationGet, clientErr.Operation)
	assert.Equal(t, int64(8), clientErr.Limit)
}

// TestInstallCheckConfig verifies the pinned POST body, optional false and zero
// preservation, and typed response decoding.
func TestInstallCheckConfig(t *testing.T) {
	t.Parallel()

	dnsIP := "192.0.2.53"
	dnsPort := uint16(53)
	emptyIP := ""
	emptyPort := uint16(0)
	autofix := false
	setStaticIP := true
	request := CheckConfigRequest{
		DNS: &CheckConfigRequestInfo{
			IP:      &dnsIP,
			Port:    &dnsPort,
			Autofix: &autofix,
		},
		Web: &CheckConfigRequestInfo{
			IP:      &emptyIP,
			Port:    &emptyPort,
			Autofix: &autofix,
		},
		SetStaticIP: &setStaticIP,
	}

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, installTestUsername, username)
		assert.Equal(t, installTestPassword, password)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, installTestPathCheckConfig, r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, installTestUserAgent, r.Header.Get("User-Agent"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.JSONEq(t, `{
			"dns":{"ip":"192.0.2.53","port":53,"autofix":false},
			"web":{"ip":"","port":0,"autofix":false},
			"set_static_ip":true
		}`, string(body))

		w.Header().Set("Content-Type", "application/json")

		_, err = io.WriteString(w, `{
			"dns":{"status":"","can_autofix":false},
			"web":{"status":"web is ready","can_autofix":true},
			"static_ip":{"static":"no","ip":"192.0.2.53","error":null}
		}`)
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 4096)

	result, err := client.InstallCheckConfig(t.Context(), request)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, CheckConfigResponseInfo{
		Status:     "",
		CanAutofix: false,
	}, result.DNS)
	assert.Equal(t, CheckConfigResponseInfo{
		Status:     "web is ready",
		CanAutofix: true,
	}, result.Web)
	require.NotNil(t, result.StaticIP.Static)
	assert.Equal(t, CheckConfigStaticIPNo, *result.StaticIP.Static)
	require.NotNil(t, result.StaticIP.IP)
	assert.Equal(t, "192.0.2.53", *result.StaticIP.IP)
	assert.Nil(t, result.StaticIP.Error)
}

// TestInstallCheckConfigOmitsNilOptionalFields verifies an all-omitted request
// still sends the required JSON object body.
func TestInstallCheckConfigOmitsNilOptionalFields(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, installTestPathCheckConfig, r.URL.Path)

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.JSONEq(t, `{}`, string(body))

		w.Header().Set("Content-Type", "application/json")

		_, err = io.WriteString(w, `{
			"dns":{"status":"","can_autofix":false},
			"web":{"status":"","can_autofix":false},
			"static_ip":{}
		}`)
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 4096)

	result, err := client.InstallCheckConfig(t.Context(), CheckConfigRequest{})

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Nil(t, result.StaticIP.Static)
	assert.Nil(t, result.StaticIP.IP)
	assert.Nil(t, result.StaticIP.Error)
}

// TestInstallCheckConfigRejectsMalformedResponse verifies response contract and
// enum failures are returned as structured JSON errors.
func TestInstallCheckConfigRejectsMalformedResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing static IP",
			body: `{"dns":{"status":"","can_autofix":false},"web":{"status":"","can_autofix":false}}`,
		},
		{
			name: "missing can autofix",
			body: `{"dns":{"status":""},"web":{"status":"","can_autofix":false},"static_ip":{}}`,
		},
		{
			name: "invalid static status",
			body: `{"dns":{"status":"","can_autofix":false},` +
				`"web":{"status":"","can_autofix":false},` +
				`"static_ip":{"static":"unknown"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")

				_, err := io.WriteString(w, test.body)
				assert.NoError(t, err)
			}))
			client := newInstallTestClient(t, server, 4096)

			result, err := client.InstallCheckConfig(t.Context(), CheckConfigRequest{})

			assert.Nil(t, result)

			clientErr := requireInstallError(t, err, ErrorKindJSON)
			assert.Equal(t, installTestOperationCheck, clientErr.Operation)
			assert.Equal(t, http.MethodPost, clientErr.Method)
		})
	}
}

// TestInstallConfigure verifies the pinned empty-response POST request.
func TestInstallConfigure(t *testing.T) {
	t.Parallel()

	configuration := InitialConfiguration{
		DNS:      AddressInfo{IP: "192.0.2.53", Port: 53},
		Web:      AddressInfo{IP: "192.0.2.2", Port: 3000},
		Username: "admin",
		Password: "password123",
	}

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()

		assert.True(t, authenticated)
		assert.Equal(t, installTestUsername, username)
		assert.Equal(t, installTestPassword, password)
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, installTestPathConfigure, r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.JSONEq(t, `{
			"dns":{"ip":"192.0.2.53","port":53},
			"web":{"ip":"192.0.2.2","port":3000},
			"username":"admin",
			"password":"password123"
		}`, string(body))

		w.WriteHeader(http.StatusOK)
	}))
	client := newInstallTestClient(t, server, 4096)

	err := client.InstallConfigure(t.Context(), configuration)

	require.NoError(t, err)
}

// TestInstallConfigureReturnsStatusError verifies structured empty-mode status
// failures.
func TestInstallConfigureReturnsStatusError(t *testing.T) {
	t.Parallel()

	const responseBody = "configuration rejected"

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusUnprocessableEntity)

		_, err := io.WriteString(w, responseBody)
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 4096)

	err := client.InstallConfigure(t.Context(), InitialConfiguration{})

	clientErr := requireInstallError(t, err, ErrorKindStatus)
	assert.Equal(t, installTestOperationApply, clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
	assert.Equal(t, responseBody, string(clientErr.Body))
}

// TestInstallConfigureEnforcesResponseLimit verifies even an empty response mode
// bounds and closes the body.
func TestInstallConfigureEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, err := io.WriteString(w, strings.Repeat("x", 32))
		assert.NoError(t, err)
	}))
	client := newInstallTestClient(t, server, 8)

	err := client.InstallConfigure(t.Context(), InitialConfiguration{})

	clientErr := requireInstallError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, installTestOperationApply, clientErr.Operation)
	assert.Equal(t, int64(8), clientErr.Limit)
}

// newInstallTestClient creates a concrete client for install tests.
func newInstallTestClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *Client {
	t.Helper()

	allOptions := make([]Option, 0, 4)

	allOptions = append(
		allOptions,
		WithHTTPClient(server.Client()),
		WithBasicAuth(installTestUsername, installTestPassword),
		WithUserAgent(installTestUserAgent),
		WithMaxResponseBodySize(limit),
	)

	client, err := NewClient(installTestServerURL, allOptions...)
	require.NoError(t, err)

	return client
}

// requireInstallError extracts and verifies an install operation error.
func requireInstallError(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}
