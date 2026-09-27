// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// roundTripFunc adapts a function to [http.RoundTripper].
type roundTripFunc func(*http.Request) (*http.Response, error)

var _ http.RoundTripper = roundTripFunc(nil)

// TestNewClientValidatesBaseURL verifies rejected base URL forms.
func TestNewClientValidatesBaseURL(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"relative URL":        "example.test",
		"missing host":        "https:///control",
		"unsupported scheme":  "ftp://example.test",
		"insecure remote URL": "http://example.test",
		"embedded user info":  "https://user:password@example.test",
		"query":               "https://example.test?token=value",
		"fragment":            "https://example.test#fragment",
		"opaque URL":          "https:example.test",
	}

	for name, baseURL := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewClient(baseURL)

			clientErr := requireClientError(t, err, ErrorKindConfig)
			assert.Contains(t, clientErr.Error(), "base URL")
		})
	}
}

// TestParseBaseURLNormalizesTrailingSlashes verifies repeated trailing path slashes are removed.
func TestParseBaseURLNormalizesTrailingSlashes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		rawURL  string
		wantURL string
	}{
		"repeated root slashes": {
			rawURL:  "HTTPS://0//",
			wantURL: "https://0",
		},
		"single path slash": {
			rawURL:  "https://example.test/api/",
			wantURL: "https://example.test/api",
		},
		"repeated path slashes": {
			rawURL:  "https://example.test/api///",
			wantURL: "https://example.test/api",
		},
		"internal repeated slashes": {
			rawURL:  "https://example.test/api//v1/",
			wantURL: "https://example.test/api//v1",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			parsedURL, err := parseBaseURL(test.rawURL)
			require.NoError(t, err)
			assert.Equal(t, test.wantURL, parsedURL.String())
			assert.False(t, strings.HasSuffix(parsedURL.Path, "/"))
		})
	}
}

// TestNewClientValidatesOptions verifies invalid functional options.
func TestNewClientValidatesOptions(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		option Option
	}{
		"nil HTTP client": {
			option: WithHTTPClient(nil),
		},
		"zero request timeout": {
			option: WithRequestTimeout(0),
		},
		"negative request timeout": {
			option: WithRequestTimeout(-1),
		},
		"zero response limit": {
			option: WithMaxResponseBodySize(0),
		},
		"negative response limit": {
			option: WithMaxResponseBodySize(-1),
		},
		"empty user agent": {
			option: WithUserAgent(""),
		},
		"user agent with newline": {
			option: WithUserAgent("adguard-client\r\nX-Injected: true"),
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewClient("https://example.test", test.option)

			clientErr := requireClientError(t, err, ErrorKindConfig)
			assert.Error(t, clientErr.Err)
		})
	}
}

// TestClientUsesInjectedHTTPClient verifies transport injection and error wrapping.
func TestClientUsesInjectedHTTPClient(t *testing.T) {
	t.Parallel()

	transportErr := errors.New("transport unavailable")
	httpClient := *http.DefaultClient

	httpClient.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, transportErr
	})

	client, err := NewClient(
		"https://example.test",
		WithHTTPClient(&httpClient),
		WithBasicAuth("test-user", "test-password"),
	)
	require.NoError(t, err)

	_, err = client.Status(t.Context())

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, string(ErrorKindStatus), clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, transportErr)
}

// RoundTrip executes the configured round-trip function.
//
// Parameters:
//   - request: The HTTP request to pass to the configured function.
//
// Returns:
//   - response: The HTTP response returned by the configured function.
//   - err: The error returned by the configured function.
func (fn roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

// ExampleNewClient demonstrates client construction.
func ExampleNewClient() {
	client, err := NewClient(
		"https://example",
		WithBasicAuth("username", "password"),
	)
	if err != nil {
		return
	}

	_ = client
	// Output:
}
