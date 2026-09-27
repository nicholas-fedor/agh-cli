// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mobileConfigRoundTripper adapts a function to an HTTP transport.
type mobileConfigRoundTripper func(*http.Request) (*http.Response, error)

// mobileConfigErrorReader returns a deterministic response-body failure.
type mobileConfigErrorReader struct{}

// mobileConfigTestHost is the host used by mobile configuration tests.
const mobileConfigTestHost = "dns.example"

// mobileConfigTestContentType is a plist-like binary media type.
const mobileConfigTestContentType = "application/x-apple-aspen-config"

// TestClientDownloadDoH verifies the DNS-over-HTTPS request and binary response.
func TestClientDownloadDoH(t *testing.T) {
	t.Parallel()

	payload := []byte{0x00, 0x01, 0xff, 'p', 'l', 'i', 's', 't', 0x00}
	clientID := "client/1"
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "test-user", username)
		assert.Equal(t, "test-password", password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/apple/doh.mobileconfig", r.URL.Path)
		assert.Equal(t, "client_id=client%2F1&host="+mobileConfigTestHost, r.URL.RawQuery)
		assert.Equal(t, "application/octet-stream", r.Header.Get("Accept"))
		assert.Equal(t, "adguard-mobile-test/1.0", r.Header.Get("User-Agent"))
		assert.Equal(t, int64(0), r.ContentLength)
		assert.Empty(t, r.Header.Get("Content-Type"))

		w.Header().Set("Content-Type", mobileConfigTestContentType)
		writeMobileConfigBytes(w, payload)
	}))
	client := newMobileConfigTestClient(t, server, "/api/", 1024)

	artifact, err := client.DownloadDoH(t.Context(), MobileConfigRequest{
		Host:     mobileConfigTestHost,
		ClientID: &clientID,
	})

	require.NoError(t, err)
	assert.Equal(t, mobileConfigTestContentType, artifact.ContentType)
	assert.Equal(t, payload, artifact.Data)
}

// TestClientDownloadDoT verifies the DNS-over-TLS request and omitted optional query.
func TestClientDownloadDoT(t *testing.T) {
	t.Parallel()

	payload := []byte("dot\x00payload")
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/apple/dot.mobileconfig", r.URL.Path)
		assert.Equal(t, "host="+mobileConfigTestHost, r.URL.RawQuery)
		assert.Equal(t, "application/octet-stream", r.Header.Get("Accept"))
		assert.NotEqual(t, "application/json", r.Header.Get("Accept"))

		w.Header().Set("Content-Type", "application/xml")
		writeMobileConfigBytes(w, payload)
	}))
	client := newMobileConfigTestClient(t, server, "/api/", 1024)

	artifact, err := client.DownloadDoT(t.Context(), MobileConfigRequest{
		Host:     mobileConfigTestHost,
		ClientID: nil,
	})

	require.NoError(t, err)
	assert.Equal(t, "application/xml", artifact.ContentType)
	assert.Equal(t, payload, artifact.Data)
}

// TestClientMobileConfigValidatesHost verifies missing and oversized hosts are rejected locally.
func TestClientMobileConfigValidatesHost(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"missing":  "",
		"blank":    "   ",
		"too long": strings.Repeat("a", 254),
	}

	for name, host := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			client := newMobileConfigTestClient(t, server, "", 1024)

			_, err := client.DownloadDoH(t.Context(), MobileConfigRequest{
				Host:     host,
				ClientID: nil,
			})

			clientErr := requireClientError(t, err, ErrorKindRequest)
			assert.Equal(t, http.MethodGet, clientErr.Method)
			assert.Zero(t, requests.Load())
		})
	}
}

// TestClientMobileConfigRejectsStatus verifies structured non-success errors retain response metadata.
func TestClientMobileConfigRejectsStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		writeMobileConfigBytes(w, []byte(`{"message":"tls server name is not configured"}`))
	}))
	client := newMobileConfigTestClient(t, server, "", 1024)

	artifact, err := client.DownloadDoH(t.Context(), MobileConfigRequest{
		Host:     mobileConfigTestHost,
		ClientID: nil,
	})

	assert.Empty(t, artifact)

	clientErr := requireClientError(t, err, ErrorKindStatus)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, http.StatusInternalServerError, clientErr.StatusCode)
	assert.Equal(t, "500 Internal Server Error", clientErr.Status)
	assert.Equal(t, "application/json", clientErr.ContentType)
	assert.JSONEq(t, `{"message":"tls server name is not configured"}`, string(clientErr.Body))
}

// TestClientMobileConfigRejectsOversizedResponse verifies the configured binary response bound.
func TestClientMobileConfigRejectsOversizedResponse(t *testing.T) {
	t.Parallel()

	payload := []byte("0123456789")
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", mobileConfigTestContentType)
		writeMobileConfigBytes(w, payload)
	}))
	client := newMobileConfigTestClient(t, server, "", 4)

	_, err := client.DownloadDoT(t.Context(), MobileConfigRequest{
		Host:     mobileConfigTestHost,
		ClientID: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, http.StatusOK, clientErr.StatusCode)
	assert.Equal(t, int64(4), clientErr.Limit)
	assert.Equal(t, mobileConfigTestContentType, clientErr.ContentType)
}

// TestClientMobileConfigHonorsCancellation verifies canceled contexts do not issue requests.
func TestClientMobileConfigHonorsCancellation(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	client := newMobileConfigTestClient(t, server, "", 1024)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.DownloadDoH(ctx, MobileConfigRequest{
		Host:     mobileConfigTestHost,
		ClientID: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindRequest)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, requests.Load())
	assert.Equal(t, http.MethodGet, clientErr.Method)
}

// TestClientMobileConfigReportsBodyReadErrors verifies body failures are structured.
func TestClientMobileConfigReportsBodyReadErrors(t *testing.T) {
	t.Parallel()

	httpClient := *http.DefaultClient

	httpClient.Transport = mobileConfigRoundTripper(func(request *http.Request) (*http.Response, error) {
		return &http.Response{
			Status:           "200 OK",
			StatusCode:       http.StatusOK,
			Proto:            "HTTP/1.1",
			ProtoMajor:       1,
			ProtoMinor:       1,
			Header:           make(http.Header),
			Body:             io.NopCloser(mobileConfigErrorReader{}),
			ContentLength:    -1,
			TransferEncoding: nil,
			Close:            false,
			Uncompressed:     false,
			Trailer:          nil,
			Request:          request,
			TLS:              nil,
		}, nil
	})

	client, err := NewClient(
		localTestServerURL,
		WithHTTPClient(&httpClient),
		WithMaxResponseBodySize(1024),
	)
	require.NoError(t, err)

	_, err = client.DownloadDoT(t.Context(), MobileConfigRequest{
		Host:     mobileConfigTestHost,
		ClientID: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindResponseBody)
	assert.Contains(t, clientErr.Error(), "read response body")
}

// RoundTrip executes the configured request function.
//
// Parameters:
//   - request: The request passed by the HTTP client.
//
// Returns:
//   - response: The configured synthetic response.
//   - err: The configured transport error.
func (rt mobileConfigRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return rt(request)
}

// Read returns a response-body failure.
//
// Parameters:
//   - buffer: The destination buffer supplied by the HTTP client.
//
// Returns:
//   - bytesRead: The number of bytes written, always zero.
//   - err: The deterministic response-body failure.
func (mobileConfigErrorReader) Read([]byte) (int, error) {
	return 0, io.ErrUnexpectedEOF
}

// newMobileConfigTestClient creates a client bound to a mobile configuration test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - basePath: The API base path appended to the local server URL.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newMobileConfigTestClient(
	t *testing.T,
	server *httptest.Server,
	basePath string,
	limit int64,
) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+basePath,
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-mobile-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// writeMobileConfigBytes writes a test response body while tolerating client disconnects.
//
// Parameters:
//   - w: The response writer receiving the bytes.
//   - body: The response body bytes to write.
func writeMobileConfigBytes(w http.ResponseWriter, body []byte) {
	_, err := w.Write(body)
	if err != nil {
		return
	}
}
