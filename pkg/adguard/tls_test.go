// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tlsTestConfigureName is the configure operation case name in TLS unit tests.
const tlsTestConfigureName = "configure"

// TestClientTLSStatus verifies TLS status decoding and its request contract.
func TestClientTLSStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "dhcp-user", username)
		assert.Equal(t, "dhcp-password", password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/tls/status", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "adguard-dhcp-test/1.0", r.Header.Get("User-Agent"))

		writeTLSStatusResponse(w)
	}))
	client := newDHCPTLSTestClient(t, server, 4096)

	config, err := client.TLSStatus(t.Context())

	require.NoError(t, err)
	require.NotNil(t, config.Enabled)
	assert.False(t, *config.Enabled)
	assert.Equal(t, "example.org", *config.ServerName)
	require.NotNil(t, config.ForceHTTPS)
	assert.False(t, *config.ForceHTTPS)
	require.NotNil(t, config.PortHTTPS)
	assert.Zero(t, *config.PortHTTPS)
	require.NotNil(t, config.PortDNSOverTLS)
	assert.Equal(t, uint16(853), *config.PortDNSOverTLS)
	assert.Nil(t, config.PortDNSOverQUIC)
	assert.Equal(t, "Y2VydGlmaWNhdGU=", *config.CertificateChain)
	assert.Nil(t, config.PrivateKey)
	require.NotNil(t, config.PrivateKeySaved)
	assert.True(t, *config.PrivateKeySaved)
	assert.Empty(t, *config.CertificatePath)
	assert.Nil(t, config.PrivateKeyPath)
	require.NotNil(t, config.ValidCertificate)
	assert.False(t, *config.ValidCertificate)
	require.NotNil(t, config.ValidChain)
	assert.True(t, *config.ValidChain)
	assert.Nil(t, config.Subject)
	assert.Equal(t, "Example CA", *config.Issuer)
	assert.Equal(t, "2026-01-01T00:00:00Z", *config.NotBefore)
	assert.Equal(t, "2027-01-01T00:00:00Z", *config.NotAfter)
	require.NotNil(t, config.DNSNames)
	assert.Empty(t, *config.DNSNames)
	require.NotNil(t, config.ValidKey)
	assert.False(t, *config.ValidKey)
	require.NotNil(t, config.KeyType)
	assert.Equal(t, TLSKeyTypeECDSA, *config.KeyType)
	assert.Empty(t, *config.WarningValidation)
	require.NotNil(t, config.ValidPair)
	assert.True(t, *config.ValidPair)
	require.NotNil(t, config.ServePlainDNS)
	assert.False(t, *config.ServePlainDNS)
}

// writeTLSStatusResponse writes the successful TLS status fixture.
//
// Parameters:
//   - w: The response writer receiving the fixture.
func writeTLSStatusResponse(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	writeBody(w, `{
		"enabled":false,
		"server_name":"example.org",
		"force_https":false,
		"port_https":0,
		"port_dns_over_tls":853,
		"port_dns_over_quic":null,
		"certificate_chain":"Y2VydGlmaWNhdGU=",
		"private_key":null,
		"private_key_saved":true,
		"certificate_path":"",
		"private_key_path":null,
		"valid_cert":false,
		"valid_chain":true,
		"subject":null,
		"issuer":"Example CA",
		"not_before":"2026-01-01T00:00:00Z",
		"not_after":"2027-01-01T00:00:00Z",
		"dns_names":[],
		"valid_key":false,
		"key_type":"ECDSA",
		"warning_validation":"",
		"valid_pair":true,
		"serve_plain_dns":false
	}`)
}

// TestClientTLSConfigureAndValidate verifies TLS configuration and validation
// request and response contracts.
func TestClientTLSConfigureAndValidate(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		path string
		call func(context.Context, *Client) error
	}{
		tlsTestConfigureName: {
			path: "/api/control/tls/configure",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSConfigure(ctx, TLSConfig{
					Enabled:           new(false),
					ServerName:        new(""),
					ForceHTTPS:        new(true),
					PortHTTPS:         new(uint16(0)),
					PortDNSOverTLS:    new(uint16(853)),
					CertificateChain:  new(""),
					PrivateKeySaved:   new(false),
					CertificatePath:   new("cert.pem"),
					DNSNames:          &[]string{},
					KeyType:           new(TLSKeyTypeRSA),
					ValidCertificate:  new(false),
					WarningValidation: new(""),
					ServePlainDNS:     new(false),
				})

				return err
			},
		},
		"validate": {
			path: "/api/control/tls/validate",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSValidate(ctx, TLSConfig{
					Enabled: new(true),
				})

				return err
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, test.path, r.URL.Path)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var body map[string]any

				assert.NoError(t, json.Unmarshal([]byte(readDHCPTLSBody(t, r)), &body))

				assertTLSRequestBody(t, name, body)

				w.Header().Set("Content-Type", "application/json")
				writeBody(w, `{"enabled":true,"key_type":"RSA","port_https":443}`)
			}))
			client := newDHCPTLSTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			require.NoError(t, err)
		})
	}
}

// assertTLSRequestBody verifies the expected TLS request fields for one
// operation.
//
// Parameters:
//   - name: The operation name selecting the expected request body.
//   - body: The decoded request body to inspect.
func assertTLSRequestBody(t *testing.T, name string, body map[string]any) {
	t.Helper()

	if name == tlsTestConfigureName {
		assert.Equal(t, false, body["enabled"])
		assert.Empty(t, body["server_name"])
		assert.Equal(t, true, body["force_https"])
		assert.InDelta(t, float64(0), body["port_https"], 0)
		assert.InDelta(t, float64(853), body["port_dns_over_tls"], 0)
		assert.NotContains(t, body, "private_key")
		assert.Equal(t, []any{}, body["dns_names"])

		return
	}

	assert.Equal(t, map[string]any{"enabled": true}, body)
}

// TestClientTLSRequiredRequestBodyAndOptionalPresence verifies that TLS
// mutation requests always carry an object and preserve explicit zero values.
func TestClientTLSRequiredRequestBodyAndOptionalPresence(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		config       TLSConfig
		expectedBody map[string]any
	}{
		"all fields omitted": {
			config:       TLSConfig{},
			expectedBody: map[string]any{},
		},
		"explicit false and zero": {
			config: TLSConfig{
				Enabled:   new(false),
				PortHTTPS: new(uint16(0)),
			},
			expectedBody: map[string]any{
				"enabled":    false,
				"port_https": float64(0),
			},
		},
	}

	for name := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, http.MethodPost, r.Method)
				assert.Equal(t, "/api/control/tls/validate", r.URL.Path)
				assert.Positive(t, r.ContentLength)
				assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

				var body map[string]any

				assert.NoError(t, json.Unmarshal([]byte(readDHCPTLSBody(t, r)), &body))
				assert.Equal(t, tests[name].expectedBody, body)
				w.Header().Set("Content-Type", "application/json")
				writeBody(w, `{}`)
			}))
			client := newDHCPTLSTestClient(t, server, 4096)

			config, err := client.TLSValidate(t.Context(), tests[name].config)

			require.NoError(t, err)
			assert.NotNil(t, config)
			assert.Nil(t, config.Enabled)
		})
	}
}

// TestClientTLSRejectsInvalidJSON verifies malformed TLS responses, null
// objects, invalid key types, and media-type failures.
func TestClientTLSRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body        string
		contentType string
		method      string
		call        func(context.Context, *Client) error
	}{
		"malformed status": {
			body:        `{"enabled":`,
			contentType: "application/json",
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
		},
		"null configure response": {
			body:        `null`,
			contentType: "application/json",
			method:      http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSConfigure(ctx, TLSConfig{})

				return err
			},
		},
		"invalid key type": {
			body:        `{"key_type":"DSA"}`,
			contentType: "application/json",
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
		},
		"wrong content type": {
			body:        `{}`,
			contentType: "text/plain",
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				writeBody(w, test.body)
			}))
			client := newDHCPTLSTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			kind := ErrorKindJSON
			if test.contentType != "application/json" {
				kind = ErrorKindContentType
			}

			clientErr := requireClientError(t, err, kind)
			assert.Equal(t, test.method, clientErr.Method)
		})
	}
}

// TestClientTLSStatusErrors verifies non-success responses for TLS status,
// configuration, and validation operations.
func TestClientTLSStatusErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		method       string
		statusCode   int
		expectedBody string
		call         func(context.Context, *Client) error
	}{
		"configure application failure": {
			method:       http.MethodPost,
			statusCode:   http.StatusInternalServerError,
			expectedBody: "apply failed",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSConfigure(ctx, TLSConfig{})

				return err
			},
		},
		"validate invalid configuration": {
			method:       http.MethodPost,
			statusCode:   http.StatusBadRequest,
			expectedBody: "invalid configuration",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSValidate(ctx, TLSConfig{})

				return err
			},
		},
		"status server failure": {
			method:       http.MethodGet,
			statusCode:   http.StatusInternalServerError,
			expectedBody: "status failed",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(test.statusCode)
				writeBody(w, `{"message":"`+test.expectedBody+`"}`)
			}))
			client := newDHCPTLSTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindStatus)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.statusCode, clientErr.StatusCode)
			assert.JSONEq(t, `{"message":"`+test.expectedBody+`"}`, string(clientErr.Body))
		})
	}
}

// TestClientTLSLimitsAndCancellation verifies TLS response limits and context
// cancellation.
func TestClientTLSLimitsAndCancellation(t *testing.T) {
	t.Parallel()

	t.Run("response limit", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			writeBody(w, `{"enabled":true}`)
		}))
		client := newDHCPTLSTestClient(t, server, 1)

		_, err := client.TLSStatus(t.Context())

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, http.MethodGet, clientErr.Method)
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

		_, err := client.TLSConfigure(ctx, TLSConfig{})

		clientErr := requireClientError(t, err, ErrorKindRequest)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.ErrorIs(t, err, context.Canceled)
	})
}
