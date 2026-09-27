// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fuzzRoundTripper adapts a function to a deterministic HTTP transport.
type fuzzRoundTripper func(*http.Request) (*http.Response, error)

// fuzzRequestCapture contains the request metadata available to fuzz assertions.
type fuzzRequestCapture struct {
	// body contains the bounded request body.
	body []byte
	// contentType contains the request media type.
	contentType string
	// method contains the request method.
	method string
	// path contains the request URL path.
	path string
	// query contains the encoded request query string.
	query string
}

const (
	// Request fuzzing bounds derived safe-search settings.
	safetyFuzzMaxRequestBytes = 64
	// Response fuzzing bounds JSON parsing.
	safetyFuzzMaxResponseBytes = 8 << 10
	// Timeout bounds every deterministic transport operation.
	fuzzResponseTimeout = time.Second
)

// FuzzSafetyRequestResponse verifies safe-search request encoding and safety status decoding.
func FuzzSafetyRequestResponse(f *testing.F) {
	f.Add(byte(0), []byte{}, []byte(`{}`))
	f.Add(byte(1), []byte{0x00, 0x01, 0x02, 0x03}, []byte(`{
		"enabled":true,"bing":false,"duckduckgo":true,"ecosia":false,
		"google":true,"pixabay":false,"yandex":true,"youtube":false
	}`))
	f.Add(byte(2), []byte{0xff}, []byte(`{"enabled":null}`))
	f.Add(byte(0), []byte{0x03}, []byte(`null`))
	f.Add(byte(1), []byte{0x00}, []byte(`{"enabled":`))

	f.Fuzz(func(t *testing.T, endpoint byte, requestData, responseData []byte) {
		exerciseSafetyFuzz(t, endpoint, requestData, responseData)
	})
}

// exerciseSafetyFuzz exercises one bounded safety request and response pair.
//
// Parameters:
//   - endpoint: The selector for one safe-browsing, parental, or safe-search status operation.
//   - requestData: The fuzz-derived request bytes.
//   - responseData: The fuzz-derived response bytes.
func exerciseSafetyFuzz(
	t *testing.T,
	endpoint byte,
	requestData []byte,
	responseData []byte,
) {
	t.Helper()

	requestData = boundedFuzzInput(requestData, safetyFuzzMaxRequestBytes)
	responseData = boundedFuzzInput(responseData, safetyFuzzMaxResponseBytes)

	client, captured := newSafetyFuzzClient(t, responseData)

	err := client.SafesearchSettings(t.Context(), fuzzSafetyConfig(requestData))

	require.NoError(t, err)
	requireSafetyFuzzSettings(t, *captured)
	requireSafetyFuzzStatus(t, client, endpoint)
}

// newSafetyFuzzClient creates an offline client that captures the settings request.
//
// Parameters:
//   - responseData: The bounded JSON body returned for status requests.
//
// Returns:
//   - client: The deterministic AdGuard client.
//   - captured: The latest captured request.
func newSafetyFuzzClient(
	t *testing.T,
	responseData []byte,
) (*Client, *fuzzRequestCapture) {
	t.Helper()

	captured := new(fuzzRequestCapture)
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		*captured = capture
		if request.Method == http.MethodPut {
			return fuzzHTTPResponse(request, http.StatusNoContent, "", nil), nil
		}

		return fuzzHTTPResponse(
			request,
			http.StatusOK,
			testResponseMediaType,
			responseData,
		), nil
	})
	client := newFuzzClient(
		t,
		transport,
		max(int64(1), int64(len(responseData))),
	)

	return client, captured
}

// requireSafetyFuzzSettings verifies the bounded safe-search settings request.
//
// Parameters:
//   - captured: The captured settings request.
func requireSafetyFuzzSettings(t *testing.T, captured fuzzRequestCapture) {
	t.Helper()
	assert.Equal(t, http.MethodPut, captured.method)
	assert.Equal(t, "/api/control/safesearch/settings", captured.path)
	assert.Empty(t, captured.query)
	assert.Equal(t, testResponseMediaType, captured.contentType)
	requireFuzzJSONBody(t, captured)
}

// requireSafetyFuzzStatus verifies one selected safety status response.
//
// Parameters:
//   - client: The deterministic AdGuard client.
//   - endpoint: The selector for one safety status operation.
func requireSafetyFuzzStatus(t *testing.T, client *Client, endpoint byte) {
	t.Helper()

	switch endpoint % 3 {
	case 0:
		status, err := client.SafebrowsingStatus(t.Context())
		requireFuzzJSONResult(
			t,
			status,
			err,
			safetySafebrowsingStatusOperation,
			http.MethodGet,
		)
	case 1:
		status, err := client.ParentalStatus(t.Context())
		requireFuzzJSONResult(
			t,
			status,
			err,
			safetyParentalStatusOperation,
			http.MethodGet,
		)
	default:
		status, err := client.SafesearchStatus(t.Context())
		requireFuzzJSONResult(
			t,
			status,
			err,
			safetySafesearchStatusOperation,
			http.MethodGet,
		)
	}
}

// RoundTrip executes the deterministic fuzz transport function.
//
// Parameters:
//   - request: The request passed by the HTTP client.
//
// Returns:
//   - response: The deterministic response returned by the function.
//   - err: The deterministic transport failure, if any.
func (transport fuzzRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

// captureFuzzRequest reads and closes one bounded request body.
//
// Parameters:
//   - request: The request captured by the deterministic transport.
//
// Returns:
//   - capture: The request metadata and body.
//   - err: A body read or close failure, if any.
func captureFuzzRequest(request *http.Request) (fuzzRequestCapture, error) {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	if readErr != nil {
		return fuzzRequestCapture{}, fmt.Errorf("read fuzz request body: %w", readErr)
	}
	if closeErr != nil {
		return fuzzRequestCapture{}, fmt.Errorf("close fuzz request body: %w", closeErr)
	}

	return fuzzRequestCapture{
		body:        bytes.Clone(body),
		contentType: request.Header.Get("Content-Type"),
		method:      request.Method,
		path:        request.URL.Path,
		query:       request.URL.RawQuery,
	}, nil
}

// newFuzzClient creates a client whose injected transport prevents network access.
//
// Parameters:
//   - transport: The deterministic transport used for every request.
//   - limit: The positive maximum response body size.
//
// Returns:
//   - client: The configured AdGuard client.
func newFuzzClient(t *testing.T, transport http.RoundTripper, limit int64) *Client {
	t.Helper()
	require.NotNil(t, transport)
	require.Positive(t, limit)

	client, err := NewClient(
		"https://fuzz.invalid/api/",
		WithHTTPClient(&http.Client{Transport: transport}),
		WithRequestTimeout(fuzzResponseTimeout),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// fuzzHTTPResponse creates a complete deterministic response for a request.
//
// Parameters:
//   - request: The request associated with the response.
//   - statusCode: The HTTP status code.
//   - contentType: The optional response media type.
//   - body: The bounded response body.
//
// Returns:
//   - response: A response suitable for an in-memory HTTP client.
func fuzzHTTPResponse(
	request *http.Request,
	statusCode int,
	contentType string,
	body []byte,
) *http.Response {
	header := make(http.Header)
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}

	return &http.Response{
		Status:        fmt.Sprintf("%d %s", statusCode, http.StatusText(statusCode)),
		StatusCode:    statusCode,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}
}

// boundedFuzzInput limits a fuzz-derived byte slice without copying it.
//
// Parameters:
//   - data: The fuzz-derived byte slice.
//   - limit: The maximum number of bytes the target will inspect.
//
// Returns:
//   - bounded: The input prefix within the limit.
func boundedFuzzInput(data []byte, limit int) []byte {
	return data[:min(len(data), limit)]
}

// requireFuzzError extracts and validates one structured client error.
//
// Parameters:
//   - err: The error returned by the public client operation.
//   - kind: The expected error classification.
//   - operation: The expected client operation name.
//   - method: The expected HTTP method.
//
// Returns:
//   - clientErr: The extracted structured error.
func requireFuzzError(
	t *testing.T,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok, "expected *Error, got %T", err)
	assert.Equal(t, kind, clientErr.Kind)
	assert.Equal(t, operation, clientErr.Operation)
	assert.Equal(t, method, clientErr.Method)

	return clientErr
}

// requireFuzzJSONResult verifies the result-or-structured-error contract of a JSON operation.
//
// Parameters:
//   - result: The decoded result pointer, which must be non-nil on success.
//   - err: The error returned by the JSON operation.
//   - operation: The expected client operation name.
//   - method: The expected HTTP method.
func requireFuzzJSONResult[T any](
	t *testing.T,
	result *T,
	err error,
	operation string,
	method string,
) {
	t.Helper()
	requireFuzzResult(t, result, err, ErrorKindJSON, operation, method)
}

// requireFuzzResult verifies a decoded result or one classified client error.
//
// Parameters:
//   - result: The decoded result pointer, which must be non-nil on success.
//   - err: The error returned by the client operation.
//   - kind: The expected error classification when decoding or encoding fails.
//   - operation: The expected client operation name.
//   - method: The expected HTTP method.
func requireFuzzResult[T any](
	t *testing.T,
	result *T,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) {
	t.Helper()

	if err == nil {
		require.NotNil(t, result)

		return
	}

	clientErr := requireFuzzError(t, err, kind, operation, method)
	require.Error(t, clientErr.Err)
}

// requireFuzzJSONBody verifies that a captured non-empty body is a JSON object.
//
// Parameters:
//   - capture: The captured request to inspect.
func requireFuzzJSONBody(t *testing.T, capture fuzzRequestCapture) {
	t.Helper()

	if len(capture.body) == 0 {
		return
	}

	var value map[string]any

	require.NoError(t, json.Unmarshal(capture.body, &value))
}

// fuzzSafetyConfig derives a bounded presence-sensitive safe-search request.
//
// Parameters:
//   - data: The bounded request input.
//
// Returns:
//   - config: A safe-search configuration with fuzz-derived optional fields.
func fuzzSafetyConfig(data []byte) SafeSearchConfig {
	return SafeSearchConfig{
		Enabled:    fuzzSafetyOptionalBool(data, 0),
		Bing:       fuzzSafetyOptionalBool(data, 1),
		DuckDuckGo: fuzzSafetyOptionalBool(data, 2),
		Ecosia:     fuzzSafetyOptionalBool(data, 3),
		Google:     fuzzSafetyOptionalBool(data, 4),
		Pixabay:    fuzzSafetyOptionalBool(data, 5),
		Yandex:     fuzzSafetyOptionalBool(data, 6),
		YouTube:    fuzzSafetyOptionalBool(data, 7),
	}
}

// fuzzSafetyOptionalBool derives one optional boolean from a bounded input byte.
//
// Parameters:
//   - data: The bounded request input.
//   - index: The field index within the request input.
//
// Returns:
//   - value: Nil when absent, or a pointer to the fuzz-derived boolean.
func fuzzSafetyOptionalBool(data []byte, index int) *bool {
	if len(data) <= index || data[index]&0b10 != 0 {
		return nil
	}

	return new(data[index]&0b01 == 0)
}
