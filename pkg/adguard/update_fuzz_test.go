// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"errors"
	"net/http"
	"testing"
)

const (
	// Server update fuzzing bounds each opaque response body.
	serverUpdateFuzzMaxResponseBytes = 4 << 10
	// ServerUpdateFuzzBaseURL is the fixed offline client base URL.
	serverUpdateFuzzBaseURL = "https://update-fuzz.invalid/api/"
	// ServerUpdateFuzzRedirectBase is the fixed origin used to resolve redirects.
	serverUpdateFuzzRedirectBase = "https://update-fuzz.invalid"
	// ServerUpdateFuzzPath is the update endpoint below the client base path.
	serverUpdateFuzzPath = "/api/control/update"
	// ServerUpdateFuzzLocation is the fixed update redirect target.
	serverUpdateFuzzLocation = "/complete/update"
	// ServerUpdateFuzzUsername is the fixed HTTP Basic authentication username.
	serverUpdateFuzzUsername = "update-fuzz-user"
	// ServerUpdateFuzzPassword is the fixed HTTP Basic authentication password.
	serverUpdateFuzzPassword = "update-fuzz-password"
	// ServerUpdateFuzzUserAgent is the fixed client User-Agent.
	serverUpdateFuzzUserAgent = "agh-cli-update-fuzz/1"
	// ServerUpdateFuzzTextMediaType is a non-JSON response media type.
	serverUpdateFuzzTextMediaType = "text/plain; charset=windows-1252"
)

// FuzzServerUpdate verifies bounded update request and opaque response semantics offline.
func FuzzServerUpdate(f *testing.F) {
	f.Add(byte(0), byte(0), []byte{})
	f.Add(byte(1), byte(1), []byte(`{`))
	f.Add(byte(2), byte(0), []byte(`{"future":`))
	f.Add(byte(3), byte(1), []byte(`null`))
	f.Add(byte(4), byte(0), []byte(`{}`))
	f.Add(byte(5), byte(1), []byte(`{"message":"redirect"}`))
	f.Add(byte(6), byte(0), []byte(`{"message":"redirect"}`))
	f.Add(byte(7), byte(0), []byte(`{"message":"invalid"}`))
	f.Add(byte(8), byte(1), []byte(`{"message":"unprocessable"}`))
	f.Add(byte(9), byte(0), []byte(`{"message":"unavailable"}`))
	f.Add(byte(0), byte(1), []byte(`malformed JSON response`))
	f.Add(byte(0), byte(1), []byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(t *testing.T, statusSelector, responseSelector byte, body []byte) {
		body = body[:min(len(body), serverUpdateFuzzMaxResponseBytes)]
		exerciseServerUpdateFuzz(
			t,
			serverUpdateFuzzHTTPStatus(statusSelector),
			serverUpdateFuzzResponseLimit(body, responseSelector),
			serverUpdateFuzzContentType(responseSelector),
			body,
		)
	})
}

// serverUpdateFuzzHTTPStatus maps one fuzz byte to a representative HTTP status.
//
// Parameters:
//   - selector: The bounded status selector.
//
// Returns:
//   - statusCode: A success, redirect, or non-success response status.
func serverUpdateFuzzHTTPStatus(selector byte) int {
	statuses := [...]int{
		http.StatusOK,
		http.StatusCreated,
		http.StatusNoContent,
		http.StatusAccepted,
		http.StatusFound,
		http.StatusTemporaryRedirect,
		http.StatusPermanentRedirect,
		http.StatusBadRequest,
		http.StatusUnprocessableEntity,
		http.StatusInternalServerError,
	}

	return statuses[int(selector)%len(statuses)]
}

// serverUpdateFuzzResponseLimit maps one fuzz byte to a positive response-body limit.
//
// Parameters:
//   - body: The bounded opaque response body.
//   - selector: The bounded response selector.
//
// Returns:
//   - limit: A limit that accepts or rejects the body.
func serverUpdateFuzzResponseLimit(body []byte, selector byte) int64 {
	limit := int64(len(body))
	if selector&1 != 0 {
		limit /= 2
	}

	return max(int64(1), limit)
}

// serverUpdateFuzzContentType maps one fuzz byte to an opaque response media type.
//
// Parameters:
//   - selector: The bounded response selector.
//
// Returns:
//   - contentType: A missing, valid, or malformed response media type.
func serverUpdateFuzzContentType(selector byte) string {
	switch selector % 4 {
	case 0:
		return ""
	case 1:
		return jsonContentType
	case 2:
		return serverUpdateFuzzTextMediaType
	default:
		return ";"
	}
}

// exerciseServerUpdateFuzz exercises one deterministic BeginUpdate request and response.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - statusCode: The deterministic response status.
//   - limit: The positive response-body limit.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func exerciseServerUpdateFuzz(
	t *testing.T,
	statusCode int,
	limit int64,
	contentType string,
	body []byte,
) {
	t.Helper()

	var (
		captured        fuzzRequestCapture
		capturedRequest *http.Request
		requestCount    int
	)

	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		captured = capture
		capturedRequest = request.Clone(t.Context())
		requestCount++

		response := fuzzHTTPResponse(request, statusCode, contentType, body)
		if statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest {
			response.Header.Set("Location", serverUpdateFuzzLocation)
		}

		return response, nil
	})
	client := newServerUpdateFuzzClient(t, transport, limit)

	err := client.BeginUpdate(t.Context())
	requireServerUpdateFuzzRequest(t, capturedRequest, captured, requestCount)
	requireServerUpdateFuzzResult(t, err, statusCode, limit, contentType, body)
}

// newServerUpdateFuzzClient creates an authenticated client that cannot reach the network.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - transport: The deterministic in-memory transport.
//   - limit: The positive response-body limit.
//
// Returns:
//   - client: The configured offline update client.
func newServerUpdateFuzzClient(
	t *testing.T,
	transport http.RoundTripper,
	limit int64,
) *Client {
	t.Helper()

	client, err := NewClient(
		serverUpdateFuzzBaseURL,
		WithHTTPClient(&http.Client{Transport: transport}),
		WithBasicAuth(serverUpdateFuzzUsername, serverUpdateFuzzPassword),
		WithUserAgent(serverUpdateFuzzUserAgent),
		WithRequestTimeout(fuzzResponseTimeout),
		WithMaxResponseBodySize(limit),
	)
	if err != nil {
		t.Fatalf("create server update fuzz client: %v", err)
	}

	return client
}

// requireServerUpdateFuzzRequest verifies the exact bodyless update request.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - request: The request observed by the offline transport.
//   - captured: The bounded request metadata and body.
//   - requestCount: The number of requests observed by the offline transport.
func requireServerUpdateFuzzRequest(
	t *testing.T,
	request *http.Request,
	captured fuzzRequestCapture,
	requestCount int,
) {
	t.Helper()

	if requestCount != 1 {
		t.Fatalf("server update request count = %d, want 1", requestCount)
	}
	if request == nil {
		t.Fatal("server update request is nil")
	}

	requireServerUpdateFuzzRequestShape(t, request, captured.body)
	requireServerUpdateFuzzRequestHeaders(t, request)
}

// requireServerUpdateFuzzRequestShape verifies the bodyless update request shape.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - request: The request observed by the offline transport.
//   - body: The bounded request body observed by the offline transport.
func requireServerUpdateFuzzRequestShape(
	t *testing.T,
	request *http.Request,
	body []byte,
) {
	t.Helper()

	if request.Method != http.MethodPost || request.URL.Path != serverUpdateFuzzPath {
		t.Fatalf(
			"update request = (%q, %q), want (%q, %q)",
			request.Method,
			request.URL.Path,
			http.MethodPost,
			serverUpdateFuzzPath,
		)
	}
	if request.URL.RawQuery != "" {
		t.Fatalf("update request query = %q, want empty", request.URL.RawQuery)
	}
	if len(body) != 0 {
		t.Fatalf("update request body = %q, want empty", body)
	}
	if request.ContentLength != 0 {
		t.Fatalf("update content length = %d, want 0", request.ContentLength)
	}
	if request.Header.Get("Content-Type") != "" {
		t.Fatalf("update content type = %q, want empty", request.Header.Get("Content-Type"))
	}
}

// requireServerUpdateFuzzRequestHeaders verifies update headers and credentials.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - request: The request observed by the offline transport.
func requireServerUpdateFuzzRequestHeaders(t *testing.T, request *http.Request) {
	t.Helper()

	if request.Header.Get("Accept") != jsonContentType {
		t.Fatalf("update accept = %q, want %q", request.Header.Get("Accept"), jsonContentType)
	}
	if request.Header.Get("User-Agent") != serverUpdateFuzzUserAgent {
		t.Fatalf("update user agent = %q, want %q", request.Header.Get("User-Agent"), serverUpdateFuzzUserAgent)
	}

	username, password, authenticated := request.BasicAuth()
	if !authenticated || username != serverUpdateFuzzUsername || password != serverUpdateFuzzPassword {
		t.Fatalf("update basic credentials = (%t, %q, %q)", authenticated, username, password)
	}
}

// requireServerUpdateFuzzResult verifies update response validation and redirect policy.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by BeginUpdate.
//   - statusCode: The deterministic response status.
//   - limit: The configured response-body limit.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func requireServerUpdateFuzzResult(
	t *testing.T,
	err error,
	statusCode int,
	limit int64,
	contentType string,
	body []byte,
) {
	t.Helper()

	switch {
	case serverUpdateFuzzIsRedirect(statusCode):
		requireServerUpdateFuzzRedirect(t, err)
	case int64(len(body)) > limit:
		requireServerUpdateFuzzTooLarge(t, err, statusCode, contentType, limit)
	case serverUpdateFuzzIsStatusFailure(statusCode):
		requireServerUpdateFuzzStatus(t, err, statusCode, contentType, body)
	default:
		requireServerUpdateFuzzNoError(t, err)
	}
}

// serverUpdateFuzzIsRedirect reports whether one status is in the redirect range.
//
// Parameters:
//   - statusCode: The deterministic response status.
//
// Returns:
//   - redirect: Whether the status is a redirect.
func serverUpdateFuzzIsRedirect(statusCode int) bool {
	return statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest
}

// serverUpdateFuzzIsStatusFailure reports whether one status is outside the success range.
//
// Parameters:
//   - statusCode: The deterministic response status.
//
// Returns:
//   - failure: Whether the status requires structured status validation.
func serverUpdateFuzzIsStatusFailure(statusCode int) bool {
	return statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices
}

// requireServerUpdateFuzzRedirect verifies one rejected update redirect.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by BeginUpdate.
func requireServerUpdateFuzzRedirect(t *testing.T, err error) {
	t.Helper()

	clientErr := requireServerUpdateFuzzError(
		t,
		err,
		ErrorKindRedirect,
		operationBeginUpdate,
		http.MethodPost,
	)
	location := serverUpdateFuzzRedirectBase + serverUpdateFuzzLocation
	if clientErr.Location != location {
		t.Fatalf("update redirect = %q, want %q", clientErr.Location, location)
	}
	if clientErr.Err == nil {
		t.Fatal("update redirect error has no cause")
	}
}

// requireServerUpdateFuzzTooLarge verifies one bounded update response error.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by BeginUpdate.
//   - statusCode: The deterministic response status.
//   - contentType: The deterministic response media type.
//   - limit: The configured response-body limit.
func requireServerUpdateFuzzTooLarge(
	t *testing.T,
	err error,
	statusCode int,
	contentType string,
	limit int64,
) {
	t.Helper()

	clientErr := requireServerUpdateFuzzError(
		t,
		err,
		ErrorKindResponseTooLarge,
		operationBeginUpdate,
		http.MethodPost,
	)
	if clientErr.StatusCode != statusCode || clientErr.ContentType != contentType {
		t.Fatalf(
			"update response metadata = (%d, %q), want (%d, %q)",
			clientErr.StatusCode,
			clientErr.ContentType,
			statusCode,
			contentType,
		)
	}
	if clientErr.Limit != limit || clientErr.Body != nil {
		t.Fatalf(
			"update size error = (limit %d, body %d), want (limit %d, body nil)",
			clientErr.Limit,
			len(clientErr.Body),
			limit,
		)
	}
}

// requireServerUpdateFuzzStatus verifies one non-success update response error.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by BeginUpdate.
//   - statusCode: The deterministic response status.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func requireServerUpdateFuzzStatus(
	t *testing.T,
	err error,
	statusCode int,
	contentType string,
	body []byte,
) {
	t.Helper()

	clientErr := requireServerUpdateFuzzError(
		t,
		err,
		ErrorKindStatus,
		operationBeginUpdate,
		http.MethodPost,
	)
	if clientErr.StatusCode != statusCode || clientErr.ContentType != contentType {
		t.Fatalf(
			"update response metadata = (%d, %q), want (%d, %q)",
			clientErr.StatusCode,
			clientErr.ContentType,
			statusCode,
			contentType,
		)
	}
	if !bytes.Equal(clientErr.Body, body) {
		t.Fatalf("update response body = %q, want %q", clientErr.Body, body)
	}
	if clientErr.Err != nil {
		t.Fatalf("update status error has cause %T %v", clientErr.Err, clientErr.Err)
	}
}

// requireServerUpdateFuzzNoError verifies one accepted update response.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by BeginUpdate.
func requireServerUpdateFuzzNoError(t *testing.T, err error) {
	t.Helper()

	if err != nil {
		t.Fatalf("server update returned an unexpected error: %T %v", err, err)
	}
}

// requireServerUpdateFuzzError verifies one structured update error classification.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error to inspect.
//   - kind: The expected error classification.
//   - operation: The expected update operation name.
//   - method: The expected HTTP method.
//
// Returns:
//   - clientErr: The extracted structured update error.
func requireServerUpdateFuzzError(
	t *testing.T,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	if !ok || clientErr == nil {
		t.Fatalf("server update error is not structured: %T %v", err, err)
	}
	if clientErr.Kind != kind || clientErr.Operation != operation || clientErr.Method != method {
		t.Fatalf(
			"update error metadata = (%q, %q, %q), want (%q, %q, %q)",
			clientErr.Kind,
			clientErr.Operation,
			clientErr.Method,
			kind,
			operation,
			method,
		)
	}

	return clientErr
}
