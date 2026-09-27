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

// dnsIntegrationSuccessCase describes one successful API exchange.
type dnsIntegrationSuccessCase struct {
	name                string
	method              string
	path                string
	requestBody         string
	responseBody        string
	responseContentType string
	invoke              func(context.Context, *adguard.Client) (any, error)
	verify              func(*testing.T, any)
}

// dnsIntegrationErrorCase describes one failing API exchange.
type dnsIntegrationErrorCase struct {
	name      string
	operation string
	method    string
	path      string
	invoke    func(context.Context, *adguard.Client) error
}

// dnsIntegrationRequest captures the request metadata used by contract assertions.
type dnsIntegrationRequest struct {
	method        string
	path          string
	rawQuery      string
	accept        string
	contentType   string
	contentLength int64
	username      string
	password      string
	userAgent     string
	body          []byte
	readErr       error
}

// dnsIntegrationResponse describes a successful integration-server response.
type dnsIntegrationResponse struct {
	body        string
	contentType string
}

const (
	// The integration username used for HTTP Basic authentication.
	dnsIntegrationUsername = "global-operator"
	// The integration password used for HTTP Basic authentication.
	dnsIntegrationPassword = "correct-horse-battery-staple"
	// The integration User-Agent identifies the client under test.
	dnsIntegrationUserAgent = "agh-cli-global-integration-test/1.0"
	// The bootstrap resolver used in realistic DNS requests.
	dnsIntegrationBootstrapDNS = "9.9.9.10"
	// The DNS-over-HTTPS resolver used in realistic DNS requests.
	dnsIntegrationDoH = "https://dns.adguard-dns.com/dns-query"
	// The DNS-over-TLS resolver used in realistic DNS requests.
	dnsIntegrationDoT = "tls://dns.quad9.net"
	// The JSON body returned for structured status errors.
	dnsIntegrationErrorBody = `{"message":"global operation rejected"}`
)

// TestClientDNSOperationsEndToEnd verifies authenticated DNS workflows through the concrete client.
func TestClientDNSOperationsEndToEnd(t *testing.T) {
	t.Parallel()

	tests := dnsIntegrationSuccessCases()

	server, requests := newDNSIntegrationSuccessServer(t, tests)
	client := newDNSIntegrationClient(t, server)

	for index := range tests {
		test := &tests[index]
		result, err := test.invoke(t.Context(), client)
		request := <-requests

		assertDNSIntegrationRequest(t, request, test)
		require.NoError(t, err, test.name)

		if test.verify != nil {
			test.verify(t, result)
		}
	}
}

// TestClientDNSStructuredErrors verifies DNS failures retain complete HTTP metadata.
func TestClientDNSStructuredErrors(t *testing.T) {
	t.Parallel()

	tests := dnsIntegrationErrorCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testDNSIntegrationError(t, &test)
		})
	}
}

// dnsIntegrationSuccessCases returns realistic DNS information, configuration, and upstream exchanges.
func dnsIntegrationSuccessCases() []dnsIntegrationSuccessCase {
	cases := dnsIntegrationConfigCases()

	return append(cases, dnsIntegrationUpstreamCases()...)
}

// dnsIntegrationConfigCases returns realistic DNS information and configuration exchanges.
func dnsIntegrationConfigCases() []dnsIntegrationSuccessCase {
	return []dnsIntegrationSuccessCase{
		{
			name:   "DNS info",
			method: http.MethodGet,
			path:   "/api/control/dns_info",
			responseBody: `{
				"bootstrap_dns":["` + dnsIntegrationBootstrapDNS + `"],
				"upstream_dns":["` + dnsIntegrationDoH + `","` + dnsIntegrationDoT + `"],
				"fallback_dns":[],
				"protection_enabled":true,
				"ratelimit":20,
				"blocking_mode":"default",
				"cache_enabled":true,
				"upstream_mode":"parallel",
				"resolve_clients":false,
				"default_local_ptr_upstreams":[]
			}`,
			responseContentType: "application/json; charset=utf-8",
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.DNSInfo(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				config, ok := result.(*adguard.DNSConfig)
				require.True(t, ok)
				assert.Equal(t, dnsIntegrationExpectedConfig(), config)
			},
		},
		{
			name:   "DNS config",
			method: http.MethodPost,
			path:   "/api/control/dns_config",
			requestBody: `{
				"bootstrap_dns":["` + dnsIntegrationBootstrapDNS + `"],
				"upstream_dns":["` + dnsIntegrationDoH + `","` + dnsIntegrationDoT + `"],
				"fallback_dns":[],
				"protection_enabled":false,
				"ratelimit":20,
				"ratelimit_whitelist":[],
				"blocking_mode":"custom_ip",
				"blocking_ipv4":"0.0.0.0",
				"blocking_ipv6":"::",
				"cache_ttl_min":0,
				"cache_enabled":true,
				"upstream_mode":"parallel",
				"resolve_clients":false,
				"local_ptr_upstreams":["192.168.1.1"],
				"upstream_timeout":10000
			}`,
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.SetDNSConfig(ctx, &adguard.DNSConfig{
					BootstrapDNS:       []string{dnsIntegrationBootstrapDNS},
					UpstreamDNS:        []string{dnsIntegrationDoH, dnsIntegrationDoT},
					FallbackDNS:        []string{},
					ProtectionEnabled:  new(false),
					RateLimit:          new(int64(20)),
					RateLimitWhitelist: []string{},
					BlockingMode:       new("custom_ip"),
					BlockingIPv4:       new("0.0.0.0"),
					BlockingIPv6:       new("::"),
					CacheTTLMin:        new(int64(0)),
					CacheEnabled:       new(true),
					UpstreamMode:       new("parallel"),
					ResolveClients:     new(false),
					LocalPTRUpstreams:  []string{"192.168.1.1"},
					UpstreamTimeout:    new(int64(10000)),
					DefaultLocalPTRUpstreams: []string{
						"127.0.0.1",
					},
				})
			},
		},
	}
}

// dnsIntegrationUpstreamCases returns the realistic upstream test exchange.
func dnsIntegrationUpstreamCases() []dnsIntegrationSuccessCase {
	return []dnsIntegrationSuccessCase{
		{
			name:   "upstream test",
			method: http.MethodPost,
			path:   "/api/control/test_upstream_dns",
			requestBody: `{
				"bootstrap_dns":["` + dnsIntegrationBootstrapDNS + `"],
				"upstream_dns":["` + dnsIntegrationDoH + `","` + dnsIntegrationDoT + `"],
				"fallback_dns":[],
				"private_upstream":["10.0.0.53"]
			}`,
			responseBody: `{
				"` + dnsIntegrationDoH + `":"OK",
				"` + dnsIntegrationDoT + `":"OK",
				"10.0.0.53":"timed out"
			}`,
			responseContentType: blockedServicesIntegrationJSONContentType,
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.TestUpstreamDNS(ctx, adguard.UpstreamConfig{
					BootstrapDNS:    []string{dnsIntegrationBootstrapDNS},
					UpstreamDNS:     []string{dnsIntegrationDoH, dnsIntegrationDoT},
					FallbackDNS:     []string{},
					PrivateUpstream: []string{"10.0.0.53"},
				})
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				results, ok := result.(map[string]string)
				require.True(t, ok)
				assert.Equal(t, map[string]string{
					dnsIntegrationDoH: "OK",
					dnsIntegrationDoT: "OK",
					"10.0.0.53":       "timed out",
				}, results)
			},
		},
	}
}

// dnsIntegrationErrorCases returns structured DNS failures.
func dnsIntegrationErrorCases() []dnsIntegrationErrorCase {
	return []dnsIntegrationErrorCase{
		{
			name:      "DNS info",
			operation: "dns_info",
			method:    http.MethodGet,
			path:      "/api/control/dns_info",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.DNSInfo(ctx)

				return err
			},
		},
		{
			name:      "DNS config",
			operation: "dns_config",
			method:    http.MethodPost,
			path:      "/api/control/dns_config",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.SetDNSConfig(ctx, &adguard.DNSConfig{})
			},
		},
		{
			name:      "upstream test",
			operation: "test_upstream_dns",
			method:    http.MethodPost,
			path:      "/api/control/test_upstream_dns",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.TestUpstreamDNS(ctx, adguard.UpstreamConfig{
					BootstrapDNS: []string{dnsIntegrationBootstrapDNS},
					UpstreamDNS:  []string{dnsIntegrationDoT},
				})

				return err
			},
		},
	}
}

// dnsIntegrationExpectedConfig returns the decoded realistic DNS information response.
func dnsIntegrationExpectedConfig() *adguard.DNSConfig {
	return &adguard.DNSConfig{
		BootstrapDNS:             []string{dnsIntegrationBootstrapDNS},
		UpstreamDNS:              []string{dnsIntegrationDoH, dnsIntegrationDoT},
		FallbackDNS:              []string{},
		ProtectionEnabled:        new(true),
		RateLimit:                new(int64(20)),
		BlockingMode:             new("default"),
		CacheEnabled:             new(true),
		UpstreamMode:             new("parallel"),
		ResolveClients:           new(false),
		DefaultLocalPTRUpstreams: []string{},
	}
}

// newDNSIntegrationSuccessServer creates the routed server and request-capture channel.
func newDNSIntegrationSuccessServer(
	t *testing.T,
	tests []dnsIntegrationSuccessCase,
) (*httptest.Server, <-chan *dnsIntegrationRequest) {
	t.Helper()

	responses := make(map[string]dnsIntegrationResponse, len(tests))
	for _, test := range tests {
		responses[test.method+" "+test.path] = dnsIntegrationResponse{
			body:        test.responseBody,
			contentType: test.responseContentType,
		}
	}

	requests := make(chan *dnsIntegrationRequest, len(tests))
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		username, password, _ := r.BasicAuth()
		body, readErr := io.ReadAll(r.Body)

		requests <- &dnsIntegrationRequest{
			method:        r.Method,
			path:          r.URL.Path,
			rawQuery:      r.URL.RawQuery,
			accept:        r.Header.Get("Accept"),
			contentType:   r.Header.Get("Content-Type"),
			contentLength: r.ContentLength,
			username:      username,
			password:      password,
			userAgent:     r.Header.Get("User-Agent"),
			body:          body,
			readErr:       readErr,
		}

		response, ok := responses[r.Method+" "+r.URL.Path]
		if !ok {
			w.WriteHeader(http.StatusNotFound)

			return
		}
		if response.contentType != "" {
			w.Header().Set("Content-Type", response.contentType)
		}

		w.WriteHeader(http.StatusOK)

		if response.body != "" {
			_, err := w.Write([]byte(response.body))
			assert.NoError(t, err)
		}
	})

	return httptest.NewTestServer(t, mux), requests
}

// newDNSIntegrationClient creates a concrete client bound to an integration server transport.
func newDNSIntegrationClient(t *testing.T, server *httptest.Server) *adguard.Client {
	t.Helper()

	baseURL := "http://127.0.0.1/api/"
	client, err := adguard.NewClient(
		baseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(dnsIntegrationUsername, dnsIntegrationPassword),
		adguard.WithUserAgent(dnsIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(1<<20),
	)
	require.NoError(t, err)

	return client
}

// assertDNSIntegrationRequest verifies the captured method, path, authentication, and payload.
func assertDNSIntegrationRequest(
	t *testing.T,
	request *dnsIntegrationRequest,
	test *dnsIntegrationSuccessCase,
) {
	t.Helper()

	// The expected media type is bound once so the header assertions read as
	// header checks rather than JSON payload checks.
	wantContentType := blockedServicesIntegrationJSONContentType

	require.NoError(t, request.readErr)
	assert.Equal(t, test.method, request.method)
	assert.Equal(t, test.path, request.path)
	assert.Empty(t, request.rawQuery)
	assert.Equal(t, dnsIntegrationUsername, request.username)
	assert.Equal(t, dnsIntegrationPassword, request.password)
	assert.Equal(t, dnsIntegrationUserAgent, request.userAgent)
	assert.Equal(t, wantContentType, request.accept)

	if test.requestBody == "" {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.contentType)
		assert.Empty(t, request.body)
	} else {
		assert.Positive(t, request.contentLength)
		assert.Equal(t, wantContentType, request.contentType)
		assert.JSONEq(t, test.requestBody, string(request.body))
	}
}

// testDNSIntegrationError verifies one operation's complete structured status error.
func testDNSIntegrationError(t *testing.T, test *dnsIntegrationErrorCase) {
	t.Helper()

	mux := http.NewServeMux()
	mux.HandleFunc(test.method+" "+test.path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnprocessableEntity)

		_, err := w.Write([]byte(dnsIntegrationErrorBody))
		assert.NoError(t, err)
	})

	server := httptest.NewTestServer(t, mux)
	client := newDNSIntegrationClient(t, server)

	err := test.invoke(t.Context(), client)

	clientErr := requireDNSIntegrationError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, test.operation, clientErr.Operation)
	assert.Equal(t, test.method, clientErr.Method)
	assert.Equal(t, "422 Unprocessable Entity", clientErr.Status)
	assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
	assert.Equal(t, "application/problem+json", clientErr.ContentType)
	assert.JSONEq(t, dnsIntegrationErrorBody, string(clientErr.Body))
	assert.Zero(t, clientErr.Limit)
	assert.Empty(t, clientErr.Location)
	assert.NoError(t, clientErr.Err)
}

// requireDNSIntegrationError requires an error of the expected kind and returns its client metadata.
func requireDNSIntegrationError(
	t *testing.T,
	err error,
	kind adguard.ErrorKind,
) *adguard.Error {
	t.Helper()

	require.Error(t, err)

	clientErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	require.Equal(t, kind, clientErr.Kind)

	return clientErr
}
