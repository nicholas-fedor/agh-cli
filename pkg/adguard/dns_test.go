// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// TlsUpstream is a stable TLS upstream test value.
	tlsUpstream = "tls://1.1.1.1"
)

// TestClientDNSInfo verifies the DNS information contract and response presence semantics.
func TestClientDNSInfo(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "test-user", username)
		assert.Equal(t, "test-password", password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/dns_info", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, "adguard-dns-test/1.0", r.Header.Get("User-Agent"))

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		writeBody(w, `{
			"bootstrap_dns": [],
			"upstream_dns": ["tls://1.1.1.1"],
			"fallback_dns": null,
			"protection_enabled": false,
			"protection_disabled_until": null,
			"cache_enabled": null,
			"default_local_ptr_upstreams": []
		}`)
	}))
	client := newDNSTestClient(t, server)

	config, err := client.DNSInfo(t.Context())

	require.NoError(t, err)
	assert.NotNil(t, config.BootstrapDNS)
	assert.Empty(t, config.BootstrapDNS)
	assert.Equal(t, []string{tlsUpstream}, config.UpstreamDNS)
	assert.Nil(t, config.FallbackDNS)
	require.NotNil(t, config.ProtectionEnabled)
	assert.False(t, *config.ProtectionEnabled)
	assert.Nil(t, config.ProtectionDisabledUntil)
	assert.Nil(t, config.CacheEnabled)
	assert.NotNil(t, config.DefaultLocalPTRUpstreams)
	assert.Empty(t, config.DefaultLocalPTRUpstreams)
}

// TestClientSetDNSConfig verifies optional field omission and empty-list preservation.
func TestClientSetDNSConfig(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/control/dns_config", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var body map[string]any

		decodeDNSRequestBody(t, r, &body)

		bootstrapDNS, exists := body["bootstrap_dns"]
		assert.True(t, exists)
		assert.Equal(t, []any{}, bootstrapDNS)
		assert.Equal(t, false, body["protection_enabled"])
		assert.NotContains(t, body, "upstream_dns")
		assert.NotContains(t, body, "rate_limit_whitelist")

		w.WriteHeader(http.StatusOK)
	}))
	client := newDNSTestClient(t, server)
	falseValue := false

	config := &DNSConfig{
		BootstrapDNS:      []string{},
		ProtectionEnabled: &falseValue,
		BlockingMode:      new("custom_ip"),
	}

	err := client.SetDNSConfig(t.Context(), config)

	require.NoError(t, err)
}

// TestClientTestUpstreamDNS verifies required request presence and result decoding.
func TestClientTestUpstreamDNS(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/api/control/test_upstream_dns", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)

		var body map[string]any

		decodeDNSRequestBody(t, r, &body)
		assert.Equal(t, []any{}, body["bootstrap_dns"])
		assert.Equal(t, []any{tlsUpstream}, body["upstream_dns"])
		assert.Equal(t, []any{}, body["fallback_dns"])
		assert.NotContains(t, body, "private_upstream")

		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"1.1.1.1":"OK","broken.example":"timeout"}`)
	}))
	client := newDNSTestClient(t, server)

	results, err := client.TestUpstreamDNS(t.Context(), UpstreamConfig{
		BootstrapDNS:    []string{},
		UpstreamDNS:     []string{tlsUpstream},
		FallbackDNS:     []string{},
		PrivateUpstream: nil,
	})

	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		fuzzSeedResolver: "OK",
		"broken.example": "timeout",
	}, results)
}

// TestClientTestUpstreamDNSRequiresFields verifies request validation happens before transport.
func TestClientTestUpstreamDNSRequiresFields(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newDNSTestClient(t, server)

	_, err := client.TestUpstreamDNS(t.Context(), UpstreamConfig{
		BootstrapDNS:    nil,
		UpstreamDNS:     []string{fuzzSeedResolver},
		FallbackDNS:     nil,
		PrivateUpstream: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Zero(t, requests.Load())
}

// TestClientDNSDecodeResponses verifies malformed JSON produces a structured error.
func TestClientDNSDecodeResponses(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeBody(w, `{"bootstrap_dns":`)
	}))
	client := newDNSTestClient(t, server)

	_, err := client.DNSInfo(t.Context())

	clientErr := requireClientError(t, err, ErrorKindJSON)
	assert.Equal(t, http.MethodGet, clientErr.Method)
}

// TestClientDNSNonSuccessStatus verifies arbitrary status errors retain bounded bodies.
func TestClientDNSNonSuccessStatus(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusConflict)
		writeBody(w, "configuration conflict")
	}))
	client := newDNSTestClient(t, server)

	config := &DNSConfig{}
	err := client.SetDNSConfig(t.Context(), config)

	clientErr := requireClientError(t, err, ErrorKindStatus)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Equal(t, http.StatusConflict, clientErr.StatusCode)
	assert.Equal(t, "configuration conflict", string(clientErr.Body))
}

// TestClientDNSCancellation verifies cancellation identity survives typed errors.
func TestClientDNSCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	client := newDNSTestClient(t, server)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.DNSInfo(ctx)

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, "dns_info", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestClientDNSRequiredResponseFields verifies missing required response members fail.
func TestClientDNSRequiredResponseFields(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		body      string
		operation string
		method    string
		request   func(context.Context, *Client) error
	}{
		"dns info null": {
			body:      testNullJSON,
			operation: "dns_info",
			method:    http.MethodGet,
			request: func(ctx context.Context, client *Client) error {
				_, err := client.DNSInfo(ctx)

				return err
			},
		},
		"upstream results null": {
			body:      testNullJSON,
			operation: "test_upstream_dns",
			method:    http.MethodPost,
			request: func(ctx context.Context, client *Client) error {
				_, err := client.TestUpstreamDNS(ctx, UpstreamConfig{
					BootstrapDNS:    []string{},
					UpstreamDNS:     []string{tlsUpstream},
					FallbackDNS:     nil,
					PrivateUpstream: nil,
				})

				return err
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				writeBody(w, test.body)
			}))
			client := newDNSTestClient(t, server)

			err := test.request(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindJSON)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
		})
	}
}

// TestClientDNSRequestTimeout verifies timeout identity through DNS operations.
func TestClientDNSRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithRequestTimeout(20*time.Millisecond),
	)
	require.NoError(t, err)

	_, err = client.DNSInfo(t.Context())

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, "dns_info", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// newDNSTestClient creates a client bound to a DNS endpoint test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//
// Returns:
//   - client: The configured AdGuard client.
func newDNSTestClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-dns-test/1.0"),
		WithMaxResponseBodySize(4096),
	)
	require.NoError(t, err)

	return client
}

// decodeDNSRequestBody decodes a JSON request body for assertions.
//
// Parameters:
//   - r: The request whose body should be decoded.
//   - result: The destination for the decoded JSON body.
func decodeDNSRequestBody(t *testing.T, r *http.Request, result any) {
	t.Helper()

	payload, err := io.ReadAll(r.Body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(payload, result))
}
