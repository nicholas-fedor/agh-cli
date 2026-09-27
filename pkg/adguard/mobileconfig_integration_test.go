// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// mobileConfigIntegrationDownload invokes one concrete mobile configuration download.
type mobileConfigIntegrationDownload func(
	*adguard.Client,
	context.Context,
	adguard.MobileConfigRequest,
) (adguard.Artifact, error)

// mobileConfigIntegrationDownloadContract describes one successful mobile configuration request.
type mobileConfigIntegrationDownloadContract struct {
	name        string
	path        string
	rawQuery    string
	clientID    *string
	contentType string
	download    mobileConfigIntegrationDownload
}

// mobileConfigIntegrationOperation identifies one mobile configuration download method.
type mobileConfigIntegrationOperation struct {
	name     string
	download mobileConfigIntegrationDownload
}

// Mobile configuration integration tests use fixed wire credentials and media types.
const (
	mobileConfigIntegrationDoHName          = "DoH"
	mobileConfigIntegrationDoTName          = "DoT"
	mobileConfigIntegrationHost             = "mobile-config.example"
	mobileConfigIntegrationUsername         = "mobile-user"
	mobileConfigIntegrationPassword         = "mobile-password"
	mobileConfigIntegrationAgent            = "mobile-integration-test/1.0"
	mobileConfigIntegrationProblemMediaType = "application/problem+json; profile=mobile"
	mobileConfigIntegrationTextMediaType    = "text/plain; charset=utf-8; profile=mobile"
)

// TestMobileConfigIntegrationDownloads verifies the complete DoH and DoT request and binary response contract.
func TestMobileConfigIntegrationDownloads(t *testing.T) {
	t.Parallel()

	for _, contract := range mobileConfigIntegrationDownloadContracts() {
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()

			testMobileConfigIntegrationDownload(t, contract)
		})
	}
}

// TestMobileConfigIntegrationRejectsMissingHost verifies both download methods reject a missing host before transport.
func TestMobileConfigIntegrationRejectsMissingHost(t *testing.T) {
	t.Parallel()

	for _, operation := range mobileConfigIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			client := newMobileConfigIntegrationClient(t, server, 1024)

			artifact, err := operation.download(client, t.Context(), adguard.MobileConfigRequest{
				Host:     "",
				ClientID: nil,
			})

			assert.Empty(t, artifact)

			clientErr := requireMobileConfigIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Zero(t, requests.Load())
		})
	}
}

// TestMobileConfigIntegrationReturnsStructuredStatusErrors verifies non-2xx responses retain bounded status metadata.
func TestMobileConfigIntegrationReturnsStructuredStatusErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		operation  mobileConfigIntegrationOperation
		statusCode int
		status     string
		body       []byte
	}{
		{
			operation: mobileConfigIntegrationOperation{
				name:     mobileConfigIntegrationDoHName,
				download: (*adguard.Client).DownloadDoH,
			},
			statusCode: http.StatusUnprocessableEntity,
			status:     "422 Unprocessable Entity",
			body:       []byte(`{"message":"host is not configured"}`),
		},
		{
			operation: mobileConfigIntegrationOperation{
				name:     mobileConfigIntegrationDoTName,
				download: (*adguard.Client).DownloadDoT,
			},
			statusCode: http.StatusServiceUnavailable,
			status:     statusIntegrationUnavailableStatus,
			body:       []byte(`{"message":"TLS service is unavailable"}`),
		},
	}

	for _, test := range tests {
		t.Run(test.operation.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", mobileConfigIntegrationProblemMediaType)
				w.WriteHeader(test.statusCode)

				_, err := w.Write(test.body)
				assert.NoError(t, err)
			}))
			client := newMobileConfigIntegrationClient(t, server, 1024)

			artifact, err := test.operation.download(
				client,
				t.Context(),
				adguard.MobileConfigRequest{Host: mobileConfigIntegrationHost, ClientID: nil},
			)

			assert.Empty(t, artifact)

			clientErr := requireMobileConfigIntegrationError(t, err, adguard.ErrorKindStatus)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Equal(t, test.statusCode, clientErr.StatusCode)
			assert.Equal(t, test.status, clientErr.Status)
			assert.Equal(t, mobileConfigIntegrationProblemMediaType, clientErr.ContentType)
			assert.Equal(t, test.body, clientErr.Body)
		})
	}
}

// TestMobileConfigIntegrationRejectsOversizedResponses verifies both download methods
// enforce the configured byte limit.
func TestMobileConfigIntegrationRejectsOversizedResponses(t *testing.T) {
	t.Parallel()

	payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff}
	limit := int64(len(payload) - 1)

	for _, operation := range mobileConfigIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)

				_, err := w.Write(payload)
				assert.NoError(t, err)
			}))
			client := newMobileConfigIntegrationClient(t, server, limit)

			artifact, err := operation.download(client, t.Context(), adguard.MobileConfigRequest{
				Host:     mobileConfigIntegrationHost,
				ClientID: nil,
			})

			assert.Empty(t, artifact)

			clientErr := requireMobileConfigIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
			assert.Equal(t, limit, clientErr.Limit)
			assert.Equal(t, "application/octet-stream", clientErr.ContentType)
		})
	}
}

// TestMobileConfigIntegrationHonorsCancellation verifies canceled contexts stop both methods before transport.
func TestMobileConfigIntegrationHonorsCancellation(t *testing.T) {
	t.Parallel()

	for _, operation := range mobileConfigIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			client := newMobileConfigIntegrationClient(t, server, 1024)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			artifact, err := operation.download(client, ctx, adguard.MobileConfigRequest{
				Host:     mobileConfigIntegrationHost,
				ClientID: nil,
			})

			assert.Empty(t, artifact)

			clientErr := requireMobileConfigIntegrationError(t, err, adguard.ErrorKindRequest)
			require.ErrorIs(t, err, context.Canceled)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Zero(t, requests.Load())
		})
	}
}

// mobileConfigIntegrationDownloadContracts returns the successful DoH and DoT request contracts.
//
// Returns:
//   - contracts: The exact request and response cases exercised by the integration test.
func mobileConfigIntegrationDownloadContracts() []mobileConfigIntegrationDownloadContract {
	clientID := "device/1+beta"
	emptyClientID := ""

	return []mobileConfigIntegrationDownloadContract{
		{
			name:        mobileConfigIntegrationDoHName + " with client identifier",
			path:        "/api/control/apple/doh.mobileconfig",
			rawQuery:    "client_id=device%2F1%2Bbeta&host=mobile-config.example",
			clientID:    &clientID,
			contentType: "application/x-apple-aspen-config; profile=doh",
			download:    (*adguard.Client).DownloadDoH,
		},
		{
			name:        mobileConfigIntegrationDoHName + " without client identifier",
			path:        "/api/control/apple/doh.mobileconfig",
			rawQuery:    "host=mobile-config.example",
			clientID:    nil,
			contentType: "",
			download:    (*adguard.Client).DownloadDoH,
		},
		{
			name:        mobileConfigIntegrationDoTName + " with empty client identifier",
			path:        "/api/control/apple/dot.mobileconfig",
			rawQuery:    "client_id=&host=mobile-config.example",
			clientID:    &emptyClientID,
			contentType: "application/octet-stream",
			download:    (*adguard.Client).DownloadDoT,
		},
		{
			name:        mobileConfigIntegrationDoTName + " without client identifier",
			path:        "/api/control/apple/dot.mobileconfig",
			rawQuery:    "host=mobile-config.example",
			clientID:    nil,
			contentType: mobileConfigIntegrationTextMediaType,
			download:    (*adguard.Client).DownloadDoT,
		},
	}
}

// testMobileConfigIntegrationDownload executes one successful mobile configuration contract.
//
// Parameters:
//   - contract: The exact request and response expectations under test.
func testMobileConfigIntegrationDownload(
	t *testing.T,
	contract mobileConfigIntegrationDownloadContract,
) {
	t.Helper()

	payload := []byte{0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 'p', 'l', 'i', 's', 't', 0x00}
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, mobileConfigIntegrationUsername, username)
		assert.Equal(t, mobileConfigIntegrationPassword, password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, contract.path, r.URL.Path)
		assert.Equal(t, contract.rawQuery, r.URL.RawQuery)
		assert.Equal(t, "application/octet-stream", r.Header.Get("Accept"))
		assert.Equal(t, mobileConfigIntegrationAgent, r.Header.Get("User-Agent"))
		assert.Zero(t, r.ContentLength)
		assert.Empty(t, r.Header.Get("Content-Type"))

		w.Header().Set("Content-Type", contract.contentType)
		w.WriteHeader(http.StatusOK)

		_, err := w.Write(payload)
		assert.NoError(t, err)
	}))
	client := newMobileConfigIntegrationClient(t, server, int64(len(payload)))

	artifact, err := contract.download(client, t.Context(), adguard.MobileConfigRequest{
		Host:     mobileConfigIntegrationHost,
		ClientID: contract.clientID,
	})

	require.NoError(t, err)
	assert.Equal(t, contract.contentType, artifact.ContentType)
	assert.Equal(t, payload, artifact.Data)
}

// mobileConfigIntegrationOperations returns the concrete DoH and DoT download operations.
//
// Returns:
//   - operations: The public client methods exercised by the integration tests.
func mobileConfigIntegrationOperations() []mobileConfigIntegrationOperation {
	return []mobileConfigIntegrationOperation{
		{
			name:     mobileConfigIntegrationDoHName,
			download: (*adguard.Client).DownloadDoH,
		},
		{
			name:     mobileConfigIntegrationDoTName,
			download: (*adguard.Client).DownloadDoT,
		},
	}
}

// newMobileConfigIntegrationClient creates an authenticated client for a mobile configuration test server.
//
// Parameters:
//   - server: The HTTP test server supplying the in-memory transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newMobileConfigIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		localTestServerURL+"/api/",
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(mobileConfigIntegrationUsername, mobileConfigIntegrationPassword),
		adguard.WithUserAgent(mobileConfigIntegrationAgent),
		adguard.WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// requireMobileConfigIntegrationError extracts a structured client error of the expected kind.
//
// Parameters:
//   - err: The error returned by a mobile configuration operation.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireMobileConfigIntegrationError(
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
