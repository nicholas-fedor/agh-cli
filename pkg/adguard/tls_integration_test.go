// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// tlsIntegrationRequest captures the request metadata crossing the HTTP boundary.
type tlsIntegrationRequest struct {
	// authenticated reports whether Basic Auth was present.
	authenticated bool
	// body contains the request body.
	body []byte
	// contentType contains the request Content-Type header.
	contentType string
	// method contains the HTTP method.
	method string
	// path contains the request URL path.
	path string
	// query contains the request URL query.
	query string
	// accept contains the request Accept header.
	accept string
	// userAgent contains the request User-Agent header.
	userAgent string
	// username contains the Basic Auth username.
	username string
	// password contains the Basic Auth password.
	password string
	// readErr contains any request-body read error.
	readErr error
}

// tlsIntegrationResponseCase describes one TLS response-body contract.
type tlsIntegrationResponseCase struct {
	// name identifies the subtest.
	name string
	// call invokes the TLS operation under test.
	call func(context.Context, *adguard.Client) error
	// operation is the expected structured error operation.
	operation string
	// method is the expected HTTP method.
	method string
	// path is the expected API path.
	path string
	// response is the response body returned by the test server.
	response string
	// wantError reports whether the response must fail decoding.
	wantError bool
}

// tlsIntegrationValidationCase describes one TLS validation error case.
type tlsIntegrationValidationCase struct {
	// name identifies the subtest.
	name string
	// call invokes the TLS operation under test.
	call func(context.Context, *adguard.Client) error
	// operation is the expected structured error operation.
	operation string
	// method is the expected HTTP method.
	method string
	// body is the response body returned by the test server.
	body string
	// message identifies the expected validation failure.
	message string
}

const (
	// The tlsIntegrationUsername is the Basic Auth username used by TLS integration tests.
	tlsIntegrationUsername = "tls-integration-user"
	// The tlsIntegrationPassword is the Basic Auth password used by TLS integration tests.
	tlsIntegrationPassword = "tls-integration-password"
	// The tlsIntegrationUserAgent is the User-Agent used by TLS integration tests.
	tlsIntegrationUserAgent = "adguard-tls-integration-test/1.0"
	// The tlsIntegrationStatusOperation identifies TLS status errors.
	tlsIntegrationStatusOperation = "tls_status"
	// The tlsIntegrationConfigureOperation identifies TLS configure errors.
	tlsIntegrationConfigureOperation = "tls_configure"
	// The tlsIntegrationValidateOperation identifies TLS validate errors.
	tlsIntegrationValidateOperation = "tls_validate"
	// The tlsIntegrationStatusPath is the TLS status endpoint path.
	tlsIntegrationStatusPath = "/api/control/tls/status"
	// The tlsIntegrationConfigurePath is the TLS configure endpoint path.
	tlsIntegrationConfigurePath = "/api/control/tls/configure"
	// The tlsIntegrationValidatePath is the TLS validate endpoint path.
	tlsIntegrationValidatePath = "/api/control/tls/validate"
	// The tlsIntegrationInvalidKeyBody is the response body for an unsupported key type.
	tlsIntegrationInvalidKeyBody = `{"key_type":"DSA"}`
	// The tlsIntegrationInvalidKeyMessage describes an unsupported key type error.
	tlsIntegrationInvalidKeyMessage = "invalid TLS key type"
)

// TestClientTLSIntegrationStatus verifies the TLS status request and pointer-presence response.
func TestClientTLSIntegrationStatus(t *testing.T) {
	t.Parallel()

	const responseBody = `{
		"enabled":false,
		"server_name":"example.org",
		"force_https":true,
		"port_https":0,
		"port_dns_over_tls":853,
		"port_dns_over_quic":null,
		"certificate_chain":"Y2VydGlmaWNhdGU=",
		"private_key":null,
		"private_key_saved":false,
		"certificate_path":"",
		"private_key_path":null,
		"valid_cert":false,
		"valid_chain":true,
		"subject":null,
		"issuer":"Example CA",
		"not_before":"2026-01-01T00:00:00Z",
		"not_after":"2027-01-01T00:00:00Z",
		"dns_names":[],
		"valid_key":true,
		"key_type":"RSA",
		"warning_validation":"",
		"valid_pair":false,
		"serve_plain_dns":true
	}`

	server, captured := newTLSIntegrationCaptureServer(t, responseBody)
	client := newTLSIntegrationClient(t, server, int64(len(responseBody)))

	config, err := client.TLSStatus(t.Context())

	require.NoError(t, err)
	require.NotNil(t, config)

	request := <-captured
	assertTLSIntegrationRequest(t, request, http.MethodGet, tlsIntegrationStatusPath, "")
	assertTLSIntegrationStatusConfig(t, config)
}

// TestClientTLSIntegrationConfigureRequest verifies the TLS configure request and JSON response contract.
func TestClientTLSIntegrationConfigureRequest(t *testing.T) {
	t.Parallel()

	config := adguard.TLSConfig{
		Enabled:           new(false),
		ServerName:        new(""),
		ForceHTTPS:        new(true),
		PortHTTPS:         new(uint16(0)),
		PortDNSOverTLS:    new(uint16(853)),
		PortDNSOverQUIC:   new(uint16(0)),
		CertificateChain:  new(""),
		PrivateKey:        new("private-key"),
		PrivateKeySaved:   new(false),
		CertificatePath:   new("cert.pem"),
		PrivateKeyPath:    new("key.pem"),
		ValidCertificate:  new(false),
		ValidChain:        new(true),
		Subject:           new(""),
		Issuer:            new(""),
		NotBefore:         new(""),
		NotAfter:          new(""),
		DNSNames:          &[]string{},
		ValidKey:          new(false),
		KeyType:           new(adguard.TLSKeyTypeECDSA),
		WarningValidation: new(""),
		ValidPair:         new(true),
		ServePlainDNS:     new(false),
	}
	const responseBody = `{"enabled":true,"key_type":"RSA","dns_names":[]}`

	server, captured := newTLSIntegrationCaptureServer(t, responseBody)
	client := newTLSIntegrationClient(t, server, int64(len(responseBody)))

	result, err := client.TLSConfigure(t.Context(), config)

	require.NoError(t, err)
	require.NotNil(t, result)

	request := <-captured
	assertTLSIntegrationRequest(t, request, http.MethodPost, tlsIntegrationConfigurePath, `{
		"enabled":false,
		"server_name":"",
		"force_https":true,
		"port_https":0,
		"port_dns_over_tls":853,
		"port_dns_over_quic":0,
		"certificate_chain":"",
		"private_key":"private-key",
		"private_key_saved":false,
		"certificate_path":"cert.pem",
		"private_key_path":"key.pem",
		"valid_cert":false,
		"valid_chain":true,
		"subject":"",
		"issuer":"",
		"not_before":"",
		"not_after":"",
		"dns_names":[],
		"valid_key":false,
		"key_type":"ECDSA",
		"warning_validation":"",
		"valid_pair":true,
		"serve_plain_dns":false
	}`)
	require.NotNil(t, result.Enabled)
	assert.True(t, *result.Enabled)
	require.NotNil(t, result.KeyType)
	assert.Equal(t, adguard.TLSKeyTypeRSA, *result.KeyType)
	require.NotNil(t, result.DNSNames)
	assert.Empty(t, *result.DNSNames)
}

// TestClientTLSIntegrationValidateRequest verifies the TLS validate request and JSON response contract.
func TestClientTLSIntegrationValidateRequest(t *testing.T) {
	t.Parallel()

	const responseBody = `{"enabled":false,"key_type":"ECDSA","port_https":0,"dns_names":[]}`

	server, captured := newTLSIntegrationCaptureServer(t, responseBody)
	client := newTLSIntegrationClient(t, server, int64(len(responseBody)))

	result, err := client.TLSValidate(t.Context(), adguard.TLSConfig{
		Enabled:   new(true),
		PortHTTPS: new(uint16(0)),
	})

	require.NoError(t, err)
	require.NotNil(t, result)

	request := <-captured
	assertTLSIntegrationRequest(t, request, http.MethodPost, tlsIntegrationValidatePath, `{
		"enabled":true,
		"port_https":0
	}`)
	require.NotNil(t, result.Enabled)
	assert.False(t, *result.Enabled)
	require.NotNil(t, result.KeyType)
	assert.Equal(t, adguard.TLSKeyTypeECDSA, *result.KeyType)
	require.NotNil(t, result.PortHTTPS)
	assert.Zero(t, *result.PortHTTPS)
	require.NotNil(t, result.DNSNames)
	assert.Empty(t, *result.DNSNames)
}

// TestClientTLSIntegrationOptionalPresence verifies absent, null, false, and true pointer values.
func TestClientTLSIntegrationOptionalPresence(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body string
		want *adguard.TLSConfig
	}{
		safetyIntegrationAbsentName: {
			body: `{}`,
			want: &adguard.TLSConfig{},
		},
		safetyIntegrationNullName: {
			body: `{"enabled":null,"server_name":null,"port_https":null,"dns_names":null,"key_type":null}`,
			want: &adguard.TLSConfig{},
		},
		"false and zero": {
			body: `{"enabled":false,"server_name":"","port_https":0,"dns_names":[],"key_type":"RSA"}`,
			want: &adguard.TLSConfig{
				Enabled:    new(false),
				ServerName: new(""),
				PortHTTPS:  new(uint16(0)),
				DNSNames:   &[]string{},
				KeyType:    new(adguard.TLSKeyTypeRSA),
			},
		},
		"true and values": {
			body: `{
				"enabled":true,
				"server_name":"example.org",
				"port_https":443,
				"dns_names":["example.org"],
				"key_type":"ECDSA"
			}`,
			want: &adguard.TLSConfig{
				Enabled:    new(true),
				ServerName: new("example.org"),
				PortHTTPS:  new(uint16(443)),
				DNSNames:   &[]string{filteringIntegrationHostName},
				KeyType:    new(adguard.TLSKeyTypeECDSA),
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server, _ := newTLSIntegrationCaptureServer(t, test.body)
			client := newTLSIntegrationClient(t, server, int64(len(test.body)))

			config, err := client.TLSStatus(t.Context())

			require.NoError(t, err)
			assert.Equal(t, test.want, config)
		})
	}
}

// TestClientTLSIntegrationEmptyAndJSONResponses verifies empty bodies fail while JSON objects succeed.
func TestClientTLSIntegrationEmptyAndJSONResponses(t *testing.T) {
	t.Parallel()

	tests := append(
		tlsIntegrationEmptyResponseCases(),
		tlsIntegrationJSONResponseCases()...,
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server, captured := newTLSIntegrationCaptureServer(t, test.response)
			client := newTLSIntegrationClient(t, server, int64(len(test.response)))

			err := test.call(t.Context(), client)
			request := <-captured
			assertTLSIntegrationRequest(t, request, test.method, test.path, `{}`)

			if test.wantError {
				clientErr := requireTLSIntegrationError(t, err, adguard.ErrorKindJSON)
				assert.Equal(t, test.operation, clientErr.Operation)
				assert.Equal(t, test.method, clientErr.Method)
				assert.ErrorContains(t, err, "decode response")

				return
			}

			require.NoError(t, err)
		})
	}
}

// tlsIntegrationEmptyResponseCases returns empty-body TLS response cases.
//
// Returns:
//   - cases: The status, configure, and validate empty-body cases.
func tlsIntegrationEmptyResponseCases() []tlsIntegrationResponseCase {
	return []tlsIntegrationResponseCase{
		{
			name: "status empty",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
			operation: tlsIntegrationStatusOperation,
			method:    http.MethodGet,
			path:      tlsIntegrationStatusPath,
			wantError: true,
		},
		{
			name: "configure empty",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSConfigure(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationConfigureOperation,
			method:    http.MethodPost,
			path:      tlsIntegrationConfigurePath,
			wantError: true,
		},
		{
			name: "validate empty",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSValidate(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationValidateOperation,
			method:    http.MethodPost,
			path:      tlsIntegrationValidatePath,
			wantError: true,
		},
	}
}

// tlsIntegrationJSONResponseCases returns empty-object TLS response cases.
//
// Returns:
//   - cases: The status, configure, and validate JSON-object cases.
func tlsIntegrationJSONResponseCases() []tlsIntegrationResponseCase {
	return []tlsIntegrationResponseCase{
		{
			name: "status JSON",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
			operation: tlsIntegrationStatusOperation,
			method:    http.MethodGet,
			path:      tlsIntegrationStatusPath,
			response:  `{}`,
		},
		{
			name: "configure JSON",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSConfigure(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationConfigureOperation,
			method:    http.MethodPost,
			path:      tlsIntegrationConfigurePath,
			response:  `{}`,
		},
		{
			name: "validate JSON",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSValidate(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationValidateOperation,
			method:    http.MethodPost,
			path:      tlsIntegrationValidatePath,
			response:  `{}`,
		},
	}
}

// TestClientTLSIntegrationValidationErrors verifies malformed, non-object, and invalid-key responses.
func TestClientTLSIntegrationValidationErrors(t *testing.T) {
	t.Parallel()

	tests := append(
		tlsIntegrationMalformedResponseCases(),
		tlsIntegrationInvalidKeyResponseCases()...,
	)

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server, _ := newTLSIntegrationCaptureServer(t, test.body)
			client := newTLSIntegrationClient(t, server, int64(len(test.body)))

			err := test.call(t.Context(), client)

			clientErr := requireTLSIntegrationError(t, err, adguard.ErrorKindJSON)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.ErrorContains(t, err, test.message)
		})
	}
}

// tlsIntegrationMalformedResponseCases returns malformed TLS response cases.
//
// Returns:
//   - cases: The malformed, null, and non-object response cases.
func tlsIntegrationMalformedResponseCases() []tlsIntegrationValidationCase {
	return []tlsIntegrationValidationCase{
		{
			name: "status malformed",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
			operation: tlsIntegrationStatusOperation,
			method:    http.MethodGet,
			body:      filteringIntegrationTruncatedJSON,
			message:   "decode response",
		},
		{
			name: "configure null",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSConfigure(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationConfigureOperation,
			method:    http.MethodPost,
			body:      safetyIntegrationNullName,
			message:   "JSON object",
		},
		{
			name: "validate array",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSValidate(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationValidateOperation,
			method:    http.MethodPost,
			body:      `[]`,
			message:   "decode response",
		},
	}
}

// tlsIntegrationInvalidKeyResponseCases returns invalid TLS key-type cases.
//
// Returns:
//   - cases: The status, configure, and validate invalid-key cases.
func tlsIntegrationInvalidKeyResponseCases() []tlsIntegrationValidationCase {
	return []tlsIntegrationValidationCase{
		{
			name: "status invalid key type",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
			operation: tlsIntegrationStatusOperation,
			method:    http.MethodGet,
			body:      tlsIntegrationInvalidKeyBody,
			message:   tlsIntegrationInvalidKeyMessage,
		},
		{
			name: "configure invalid key type",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSConfigure(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationConfigureOperation,
			method:    http.MethodPost,
			body:      tlsIntegrationInvalidKeyBody,
			message:   tlsIntegrationInvalidKeyMessage,
		},
		{
			name: "validate invalid key type",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSValidate(ctx, adguard.TLSConfig{})

				return err
			},
			operation: tlsIntegrationValidateOperation,
			method:    http.MethodPost,
			body:      tlsIntegrationInvalidKeyBody,
			message:   tlsIntegrationInvalidKeyMessage,
		},
	}
}

// TestClientTLSIntegrationStructuredStatusErrors verifies HTTP failures retain structured metadata.
func TestClientTLSIntegrationStructuredStatusErrors(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		call       func(context.Context, *adguard.Client) error
		operation  string
		method     string
		path       string
		statusCode int
		body       string
	}{
		filteringIntegrationStatusName: {
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSStatus(ctx)

				return err
			},
			operation:  tlsIntegrationStatusOperation,
			method:     http.MethodGet,
			path:       tlsIntegrationStatusPath,
			statusCode: http.StatusInternalServerError,
			body:       `{"message":"status failed"}`,
		},
		adguardIntegrationConfigureName: {
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSConfigure(ctx, adguard.TLSConfig{})

				return err
			},
			operation:  tlsIntegrationConfigureOperation,
			method:     http.MethodPost,
			path:       tlsIntegrationConfigurePath,
			statusCode: http.StatusBadRequest,
			body:       `{"message":"configuration failed"}`,
		},
		"validate": {
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TLSValidate(ctx, adguard.TLSConfig{})

				return err
			},
			operation:  tlsIntegrationValidateOperation,
			method:     http.MethodPost,
			path:       tlsIntegrationValidatePath,
			statusCode: http.StatusUnprocessableEntity,
			body:       `{"message":"validation failed"}`,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := newTLSIntegrationResponseServer(
				t,
				test.statusCode,
				blockedServicesIntegrationProblemContentType,
				test.body,
			)
			client := newTLSIntegrationClient(t, server, int64(len(test.body)))

			err := test.call(t.Context(), client)

			clientErr := requireTLSIntegrationError(t, err, adguard.ErrorKindStatus)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.statusCode, clientErr.StatusCode)
			assert.Contains(t, clientErr.Status, http.StatusText(test.statusCode))
			assert.Equal(t, blockedServicesIntegrationProblemContentType, clientErr.ContentType)
			assert.JSONEq(t, test.body, string(clientErr.Body))
			assert.ErrorContains(t, err, http.StatusText(test.statusCode))
		})
	}
}

// assertTLSIntegrationStatusConfig verifies the decoded TLS status fields.
//
// Parameters:
//   - t: The test receiving assertion failures.
//   - config: The decoded TLS status to inspect.
func assertTLSIntegrationStatusConfig(t *testing.T, config *adguard.TLSConfig) {
	t.Helper()

	require.NotNil(t, config.Enabled)
	assert.False(t, *config.Enabled)
	require.NotNil(t, config.ServerName)
	assert.Equal(t, "example.org", *config.ServerName)
	require.NotNil(t, config.ForceHTTPS)
	assert.True(t, *config.ForceHTTPS)
	require.NotNil(t, config.PortHTTPS)
	assert.Zero(t, *config.PortHTTPS)
	require.NotNil(t, config.PortDNSOverTLS)
	assert.Equal(t, uint16(853), *config.PortDNSOverTLS)
	assert.Nil(t, config.PortDNSOverQUIC)
	require.NotNil(t, config.CertificateChain)
	assert.Equal(t, "Y2VydGlmaWNhdGU=", *config.CertificateChain)
	assert.Nil(t, config.PrivateKey)
	require.NotNil(t, config.PrivateKeySaved)
	assert.False(t, *config.PrivateKeySaved)
	require.NotNil(t, config.CertificatePath)
	assert.Empty(t, *config.CertificatePath)
	assert.Nil(t, config.PrivateKeyPath)
	require.NotNil(t, config.ValidCertificate)
	assert.False(t, *config.ValidCertificate)
	require.NotNil(t, config.ValidChain)
	assert.True(t, *config.ValidChain)
	assert.Nil(t, config.Subject)
	require.NotNil(t, config.Issuer)
	assert.Equal(t, "Example CA", *config.Issuer)
	require.NotNil(t, config.NotBefore)
	assert.Equal(t, "2026-01-01T00:00:00Z", *config.NotBefore)
	require.NotNil(t, config.NotAfter)
	assert.Equal(t, "2027-01-01T00:00:00Z", *config.NotAfter)
	require.NotNil(t, config.DNSNames)
	assert.Empty(t, *config.DNSNames)
	require.NotNil(t, config.ValidKey)
	assert.True(t, *config.ValidKey)
	require.NotNil(t, config.KeyType)
	assert.Equal(t, adguard.TLSKeyTypeRSA, *config.KeyType)
	require.NotNil(t, config.WarningValidation)
	assert.Empty(t, *config.WarningValidation)
	require.NotNil(t, config.ValidPair)
	assert.False(t, *config.ValidPair)
	require.NotNil(t, config.ServePlainDNS)
	assert.True(t, *config.ServePlainDNS)
}

// newTLSIntegrationClient creates an authenticated client bound to a TLS integration server.
//
// Parameters:
//   - t: The test receiving construction failures.
//   - server: The test server supplying the HTTP transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newTLSIntegrationClient(t *testing.T, server *httptest.Server, limit int64) *adguard.Client {
	t.Helper()

	if limit < 1 {
		limit = 1
	}

	client, err := adguard.NewClient(
		blockedServicesIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(tlsIntegrationUsername, tlsIntegrationPassword),
		adguard.WithUserAgent(tlsIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// newTLSIntegrationCaptureServer creates a server that captures one request and returns a JSON body.
//
// Parameters:
//   - t: The test owning the server.
//   - responseBody: The response body returned by the server.
//
// Returns:
//   - server: The HTTP test server.
//   - captured: A channel containing the captured request metadata.
func newTLSIntegrationCaptureServer(
	t *testing.T,
	responseBody string,
) (*httptest.Server, <-chan tlsIntegrationRequest) {
	t.Helper()

	captured := make(chan tlsIntegrationRequest, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		username, password, authenticated := r.BasicAuth()

		captured <- tlsIntegrationRequest{
			authenticated: authenticated,
			body:          body,
			contentType:   r.Header.Get("Content-Type"),
			method:        r.Method,
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			accept:        r.Header.Get("Accept"),
			userAgent:     r.Header.Get("User-Agent"),
			username:      username,
			password:      password,
			readErr:       readErr,
		}

		w.Header().Set("Content-Type", blockedServicesIntegrationJSONContentType)
		writeTLSIntegrationBody(w, responseBody)
	}))

	return server, captured
}

// newTLSIntegrationResponseServer creates a server that returns a fixed HTTP response.
//
// Parameters:
//   - t: The test owning the server.
//   - statusCode: The HTTP status code returned by the server.
//   - contentType: The response Content-Type header.
//   - body: The response body.
//
// Returns:
//   - server: The HTTP test server.
func newTLSIntegrationResponseServer(
	t *testing.T,
	statusCode int,
	contentType string,
	body string,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(statusCode)
		writeTLSIntegrationBody(w, body)
	}))
}

// requireTLSIntegrationError extracts and verifies a structured client error.
//
// Parameters:
//   - t: The test receiving assertion failures.
//   - err: The error to inspect.
//   - kind: The expected client error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireTLSIntegrationError(t *testing.T, err error, kind adguard.ErrorKind) *adguard.Error {
	t.Helper()

	clientErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}

// writeTLSIntegrationBody writes a response body while tolerating client disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeTLSIntegrationBody(w http.ResponseWriter, body string) {
	_, err := w.Write([]byte(body))
	if err != nil {
		return
	}
}

// assertTLSIntegrationRequest verifies one TLS request's transport and JSON contract.
//
// Parameters:
//   - t: The test receiving assertion failures.
//   - request: The captured request to inspect.
//   - method: The expected HTTP method.
//   - path: The expected API path.
//   - body: The expected JSON body, or an empty string when no body is expected.
func assertTLSIntegrationRequest(t *testing.T, request tlsIntegrationRequest, method, path, body string) {
	t.Helper()

	// The expected media type is bound once so the header assertions read as
	// header checks rather than JSON payload checks.
	wantContentType := blockedServicesIntegrationJSONContentType

	require.NoError(t, request.readErr)
	assert.True(t, request.authenticated)
	assert.Equal(t, tlsIntegrationUsername, request.username)
	assert.Equal(t, tlsIntegrationPassword, request.password)
	assert.Equal(t, method, request.method)
	assert.Equal(t, path, request.path)
	assert.Empty(t, request.query)
	assert.Equal(t, wantContentType, request.accept)
	assert.Equal(t, tlsIntegrationUserAgent, request.userAgent)

	if method == http.MethodGet {
		assert.Empty(t, request.contentType)
		assert.Empty(t, request.body)

		return
	}

	assert.Equal(t, wantContentType, request.contentType)
	assert.NotEmpty(t, request.body)
	assert.JSONEq(t, body, string(request.body))
}
