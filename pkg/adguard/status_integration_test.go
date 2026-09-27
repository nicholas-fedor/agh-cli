// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// statusIntegrationErrorCase describes one invalid status response.
type statusIntegrationErrorCase struct {
	// name identifies the subtest.
	name string
	// statusCode is the response status code.
	statusCode int
	// contentType is the raw response media type.
	contentType string
	// body is the response body returned by the test server.
	body string
	// wantKind is the expected structured error kind.
	wantKind adguard.ErrorKind
	// wantStatusCode is the expected retained HTTP status code.
	wantStatusCode int
	// wantContentType is the expected retained response media type.
	wantContentType string
	// wantStatus is the expected HTTP status line.
	wantStatus string
	// wantBody is the expected retained response body.
	wantBody string
}

const (
	// Status integration tests authenticate with this username.
	statusIntegrationUsername = "status-user"
	// Status integration tests authenticate with this password.
	statusIntegrationPassword = "status-password"
	// Status integration tests send this User-Agent value.
	statusIntegrationUserAgent = "adguard-status-integration-test/1.0"
	// The status integration base URL is a plaintext loopback host routed
	// through the test transport.
	statusIntegrationBaseURL = "http://127.0.0.2"
	// The client must send the status request to this exact path.
	statusIntegrationPath = "/control/status"
	// Successful status responses use this charset-qualified JSON media type.
	statusIntegrationJSONCharsetContentType = "application/json;charset=utf-8"
	// This media type is a valid non-JSON response type the client rejects.
	statusIntegrationTextContentType = "text/html; charset=utf-8"
	// This status line is retained verbatim by non-success status errors.
	statusIntegrationOKStatus = "200 OK"
	// This status line is retained verbatim by a 503 response.
	statusIntegrationUnavailableStatus = "503 Service Unavailable"
	// This bounded body is returned by the non-success response case.
	statusIntegrationProblemBody = `{"message":"status endpoint unavailable"}`
	// Cancellation coordination must complete within this timeout.
	statusIntegrationCancellationTimeout = time.Second
	// Status integration responses use this default bounded size.
	statusIntegrationResponseLimit int64 = 4096
	// This fixture is a realistic complete status response.
	statusIntegrationResponseJSON = `{
		"dns_addresses": ["192.0.2.30", "2001:db8::30"],
		"dns_port": 53,
		"http_port": 3000,
		"language": "en",
		"protection_enabled": true,
		"protection_disabled_duration": 0,
		"dhcp_available": false,
		"running": true,
		"version": "v0.107.52",
		"start_time": 1758782400000,
		"future_field": {"ignored": true}
	}`
	// This fixture contains every required status member.
	statusIntegrationRequiredJSON = `{
		"dns_addresses": [],
		"dns_port": 53,
		"http_port": 3000,
		"language": "en",
		"protection_enabled": false,
		"running": true,
		"version": "v0.107.52"
	}`
	// This fixture contains null for every optional status member.
	statusIntegrationNullOptionalJSON = `{
		"dns_addresses": [],
		"dns_port": 53,
		"http_port": 3000,
		"language": "en",
		"protection_enabled": false,
		"protection_disabled_duration": null,
		"dhcp_available": null,
		"running": true,
		"version": "v0.107.52",
		"start_time": null
	}`
)

// TestStatusIntegrationDecodesRealisticResponse verifies an authenticated request
// uses the exact status path and decodes required and optional members.
func TestStatusIntegrationDecodesRealisticResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, statusIntegrationUsername, username)
		assert.Equal(t, statusIntegrationPassword, password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, statusIntegrationPath, r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, []string{"application/json"}, r.Header.Values("Accept"))
		assert.Equal(t, statusIntegrationUserAgent, r.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", statusIntegrationJSONCharsetContentType)
		writeStatusIntegrationBody(w, statusIntegrationResponseJSON)
	}))
	client := newStatusIntegrationClient(t, server)

	status, err := client.Status(t.Context())

	require.NoError(t, err)
	require.NotNil(t, status)
	assert.Equal(t, []string{"192.0.2.30", "2001:db8::30"}, status.DNSAddresses)
	assert.Equal(t, uint16(53), status.DNSPort)
	assert.Equal(t, uint16(3000), status.HTTPPort)
	assert.Equal(t, "en", status.Language)
	assert.True(t, status.ProtectionEnabled)
	require.NotNil(t, status.ProtectionDisabledDuration)
	assert.Zero(t, *status.ProtectionDisabledDuration)
	require.NotNil(t, status.DHCPAvailable)
	assert.False(t, *status.DHCPAvailable)
	assert.True(t, status.Running)
	assert.Equal(t, "v0.107.52", status.Version)
	require.NotNil(t, status.StartTime)
	assert.InDelta(t, float64(1_758_782_400_000), *status.StartTime, 0)
}

// TestStatusIntegrationHandlesOptionalFields verifies omitted and null optional
// status members remain absent.
func TestStatusIntegrationHandlesOptionalFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "omitted", body: statusIntegrationRequiredJSON},
		{name: "explicit null", body: statusIntegrationNullOptionalJSON},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				writeStatusIntegrationBody(w, test.body)
			}))
			client := newStatusIntegrationClient(t, server)

			status, err := client.Status(t.Context())

			require.NoError(t, err)
			require.NotNil(t, status)
			assert.Empty(t, status.DNSAddresses)
			assert.Equal(t, uint16(53), status.DNSPort)
			assert.Equal(t, uint16(3000), status.HTTPPort)
			assert.Equal(t, "en", status.Language)
			assert.False(t, status.ProtectionEnabled)
			assert.Nil(t, status.ProtectionDisabledDuration)
			assert.Nil(t, status.DHCPAvailable)
			assert.True(t, status.Running)
			assert.Equal(t, "v0.107.52", status.Version)
			assert.Nil(t, status.StartTime)
		})
	}
}

// TestStatusIntegrationReturnsTypedResponseErrors verifies malformed payloads,
// invalid content types, invalid required fields, and non-success responses
// produce typed errors with applicable response metadata.
func TestStatusIntegrationReturnsTypedResponseErrors(t *testing.T) {
	t.Parallel()

	cases := statusIntegrationErrorCases()
	for index := range cases {
		test := &cases[index]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				w.WriteHeader(test.statusCode)
				writeStatusIntegrationBody(w, test.body)
			}))
			client := newStatusIntegrationClient(t, server)

			status, err := client.Status(t.Context())

			assert.Nil(t, status)

			clientErr := requireStatusIntegrationError(t, err, test.wantKind)
			assert.Equal(t, "status", clientErr.Operation)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Equal(t, test.wantStatusCode, clientErr.StatusCode)
			assert.Equal(t, test.wantStatus, clientErr.Status)
			assert.Equal(t, test.wantContentType, clientErr.ContentType)
			assert.Equal(t, test.wantBody, string(clientErr.Body))
		})
	}
}

// TestStatusIntegrationEnforcesResponseLimit verifies the configured bound wins
// before JSON decoding for an oversized successful response.
func TestStatusIntegrationEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeStatusIntegrationBody(w, statusIntegrationResponseJSON)
	}))
	limit := int64(len(statusIntegrationResponseJSON)) - 1
	client := newStatusIntegrationClient(
		t,
		server,
		adguard.WithMaxResponseBodySize(limit),
	)

	status, err := client.Status(t.Context())

	assert.Nil(t, status)

	clientErr := requireStatusIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
	assert.Equal(t, "status", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Contains(t, clientErr.ContentType, "application/json")
	assert.Equal(t, limit, clientErr.Limit)
}

// TestStatusIntegrationPropagatesCancellation verifies cancellation of an
// in-flight request remains matchable through the typed request error.
func TestStatusIntegrationPropagatesCancellation(t *testing.T) {
	t.Parallel()

	requestStarted := make(chan struct{})
	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		close(requestStarted)
		<-r.Context().Done()
	}))
	client := newStatusIntegrationClient(t, server)
	ctx, cancel := context.WithCancel(t.Context())

	defer cancel()

	result := make(chan error, 1)

	go func() {
		_, err := client.Status(ctx)
		result <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(statusIntegrationCancellationTimeout):
		t.Fatal("status request did not reach the test server")
	}

	cancel()

	var err error

	select {
	case err = <-result:
	case <-time.After(statusIntegrationCancellationTimeout):
		t.Fatal("status request did not return after cancellation")
	}

	clientErr := requireStatusIntegrationError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, "status", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.Canceled)
}

// statusIntegrationErrorCases returns representative invalid response cases.
//
// Returns:
//   - cases: The malformed, content-type, required-field, and status failures.
func statusIntegrationErrorCases() []statusIntegrationErrorCase {
	return []statusIntegrationErrorCase{
		{
			name:            "truncated JSON",
			statusCode:      http.StatusOK,
			contentType:     statusIntegrationJSONCharsetContentType,
			body:            `{"dns_addresses":`,
			wantKind:        adguard.ErrorKindJSON,
			wantStatusCode:  0,
			wantContentType: "",
			wantStatus:      "",
			wantBody:        "",
		},
		{
			name:            "wrong content type",
			statusCode:      http.StatusOK,
			contentType:     statusIntegrationTextContentType,
			body:            statusIntegrationResponseJSON,
			wantKind:        adguard.ErrorKindContentType,
			wantStatusCode:  http.StatusOK,
			wantContentType: statusIntegrationTextContentType,
			wantStatus:      statusIntegrationOKStatus,
			wantBody:        "",
		},
		{
			name:            "malformed content type",
			statusCode:      http.StatusOK,
			contentType:     "application/json; charset",
			body:            statusIntegrationResponseJSON,
			wantKind:        adguard.ErrorKindContentType,
			wantStatusCode:  http.StatusOK,
			wantContentType: "application/json; charset",
			wantStatus:      statusIntegrationOKStatus,
			wantBody:        "",
		},
		{
			name:        "missing required field",
			statusCode:  http.StatusOK,
			contentType: statusIntegrationJSONCharsetContentType,
			body: `{
				"dns_addresses": [],
				"dns_port": 53,
				"http_port": 3000,
				"language": "en",
				"protection_enabled": false,
				"running": true
			}`,
			wantKind:        adguard.ErrorKindJSON,
			wantStatusCode:  0,
			wantContentType: "",
			wantStatus:      "",
			wantBody:        "",
		},
		{
			name:            "non-success response",
			statusCode:      http.StatusServiceUnavailable,
			contentType:     "application/problem+json; charset=utf-8",
			body:            statusIntegrationProblemBody,
			wantKind:        adguard.ErrorKindStatus,
			wantStatusCode:  http.StatusServiceUnavailable,
			wantContentType: "application/problem+json; charset=utf-8",
			wantStatus:      statusIntegrationUnavailableStatus,
			wantBody:        statusIntegrationProblemBody,
		},
	}
}

// newStatusIntegrationClient creates a concrete client for a test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - options: Additional client options applied after the integration defaults.
//
// Returns:
//   - client: The configured AdGuard client.
func newStatusIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	options ...adguard.Option,
) *adguard.Client {
	t.Helper()

	allOptions := make([]adguard.Option, 0, 4+len(options))

	allOptions = append(
		allOptions,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(statusIntegrationUsername, statusIntegrationPassword),
		adguard.WithUserAgent(statusIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(statusIntegrationResponseLimit),
	)
	allOptions = append(allOptions, options...)

	client, err := adguard.NewClient(statusIntegrationBaseURL, allOptions...)
	require.NoError(t, err)

	return client
}

// requireStatusIntegrationError extracts and verifies a structured client error.
//
// Parameters:
//   - err: The error returned by Status.
//   - kind: The expected client error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireStatusIntegrationError(
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

// writeStatusIntegrationBody writes a response body while tolerating disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeStatusIntegrationBody(w http.ResponseWriter, body string) {
	_, err := w.Write([]byte(body))
	if err != nil {
		return
	}
}
