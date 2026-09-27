// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"net/http"
	"testing"
	"unicode/utf8"
)

const (
	// Auth fuzzing bounds each credential value.
	authFuzzMaxStringBytes = 512
	// Auth fuzzing bounds each opaque response body.
	authFuzzMaxResponseBytes = 4 << 10
	// AuthFuzzBaseURL is the fixed offline client base URL.
	authFuzzBaseURL = "https://fuzz.invalid/api/"
	// AuthFuzzRedirectBase is the fixed origin used to resolve rejected redirects.
	authFuzzRedirectBase = "https://fuzz.invalid"
	// AuthFuzzLoginPath is the login endpoint below the client base path.
	authFuzzLoginPath = "/api/control/login"
	// AuthFuzzLogoutPath is the logout endpoint below the client base path.
	authFuzzLogoutPath = "/api/control/logout"
	// AuthFuzzLoginLocation is the fixed login redirect target.
	authFuzzLoginLocation = "/complete/login"
	// AuthFuzzLogoutLocation is the fixed logout redirect target.
	authFuzzLogoutLocation = "/complete/logout"
	// AuthFuzzUsername is the fixed HTTP Basic authentication username.
	authFuzzUsername = "auth-fuzz-user"
	// AuthFuzzPassword is the fixed HTTP Basic authentication password.
	authFuzzPassword = "auth-fuzz-password"
	// AuthFuzzUserAgent is the fixed client User-Agent.
	authFuzzUserAgent = "agh-cli-auth-fuzz/1"
	// AuthFuzzTextMediaType is a non-JSON response media type.
	authFuzzTextMediaType = "text/plain; charset=iso-8859-1"
)

// FuzzAuth verifies bounded login and logout request and response semantics offline.
func FuzzAuth(f *testing.F) {
	f.Add("", "", byte(0), byte(0), []byte{})
	f.Add("admin", "secret", byte(1), byte(1), []byte(`{`))
	f.Add("üser", "päss", byte(2), byte(0), []byte(`null`))
	f.Add("", "secret", byte(3), byte(1), []byte(`{}`))
	f.Add("admin", "", byte(4), byte(1), []byte(`{"message":"redirect"}`))
	f.Add("admin", "secret", byte(5), byte(0), []byte(`{"message":"redirect"}`))
	f.Add("admin", "secret", byte(6), byte(1), []byte(`{"message":"redirect"}`))
	f.Add("admin", "secret", byte(7), byte(0), []byte(`{"message":"invalid"}`))
	f.Add("admin", "secret", byte(8), byte(1), []byte(`{"message":"unavailable"}`))
	f.Add("", "", byte(0), byte(1), []byte(`malformed JSON response`))
	f.Add("admin", "secret", byte(0), byte(1), []byte{0xff, 0xfe, 0xfd})

	f.Fuzz(func(
		t *testing.T,
		name string,
		password string,
		statusSelector byte,
		responseSelector byte,
		body []byte,
	) {
		if !authFuzzInputBounded(name, password, body) {
			return
		}

		exerciseAuthFuzz(
			t,
			Login{Name: name, Password: password},
			authFuzzHTTPStatus(statusSelector),
			authFuzzResponseLimit(body, responseSelector),
			authFuzzContentType(responseSelector),
			body[:min(len(body), authFuzzMaxResponseBytes)],
		)
	})
}

// authFuzzInputBounded reports whether one auth fuzz input has a supported size and encoding.
//
// Parameters:
//   - name: The fuzzed login name.
//   - password: The fuzzed login password.
//   - body: The fuzzed opaque response body.
//
// Returns:
//   - bounded: Whether the input can be exercised safely.
func authFuzzInputBounded(name, password string, body []byte) bool {
	return len(name) <= authFuzzMaxStringBytes &&
		len(password) <= authFuzzMaxStringBytes &&
		utf8.ValidString(name) &&
		utf8.ValidString(password) &&
		len(body) <= authFuzzMaxResponseBytes
}

// authFuzzHTTPStatus maps one fuzz byte to a representative HTTP status.
//
// Parameters:
//   - selector: The bounded status selector.
//
// Returns:
//   - statusCode: A success, redirect, or non-success response status.
func authFuzzHTTPStatus(selector byte) int {
	switch selector % 8 {
	case 0:
		return http.StatusOK
	case 1:
		return http.StatusCreated
	case 2:
		return http.StatusNoContent
	case 3:
		return http.StatusFound
	case 4:
		return http.StatusTemporaryRedirect
	case 5:
		return http.StatusPermanentRedirect
	case 6:
		return http.StatusBadRequest
	default:
		return http.StatusInternalServerError
	}
}

// authFuzzResponseLimit maps one fuzz byte to a positive response-body limit.
//
// Parameters:
//   - body: The bounded opaque response body.
//   - selector: The bounded response selector.
//
// Returns:
//   - limit: A limit that accepts or rejects the body.
func authFuzzResponseLimit(body []byte, selector byte) int64 {
	limit := int64(len(body))
	if selector&1 != 0 {
		limit /= 2
	}

	return max(int64(1), limit)
}

// authFuzzContentType maps one fuzz byte to an opaque response media type.
//
// Parameters:
//   - selector: The bounded response selector.
//
// Returns:
//   - contentType: A missing, valid, or malformed response media type.
func authFuzzContentType(selector byte) string {
	switch selector % 4 {
	case 0:
		return ""
	case 1:
		return jsonContentType
	case 2:
		return authFuzzTextMediaType
	default:
		return ";"
	}
}

// exerciseAuthFuzz exercises login and logout against one deterministic response.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - login: The bounded login request.
//   - statusCode: The deterministic response status.
//   - limit: The positive response-body limit.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func exerciseAuthFuzz(
	t *testing.T,
	login Login,
	statusCode int,
	limit int64,
	contentType string,
	body []byte,
) {
	t.Helper()

	requests := make([]*http.Request, 0, 2)
	bodies := make([][]byte, 0, 2)
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		requests = append(requests, request.Clone(t.Context()))
		bodies = append(bodies, capture.body)

		response := fuzzHTTPResponse(request, statusCode, contentType, body)
		if statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest {
			response.Header.Set("Location", authFuzzRedirectLocation(request.URL.Path))
		}

		return response, nil
	})
	client := newAuthFuzzClient(t, transport, limit)

	err := client.Login(t.Context(), login)
	requireAuthFuzzLoginRequest(t, requests, bodies, login)
	requireAuthFuzzLoginResult(t, err, statusCode, limit, contentType, body)

	requests = requests[:0]
	bodies = bodies[:0]

	err = client.Logout(t.Context())
	requireAuthFuzzLogoutRequest(t, requests, bodies)
	requireAuthFuzzLogoutResult(t, err, statusCode, limit, contentType, body)
}

// newAuthFuzzClient creates an authenticated client that cannot reach the network.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - transport: The deterministic in-memory transport.
//   - limit: The positive response-body limit.
//
// Returns:
//   - client: The configured offline auth client.
func newAuthFuzzClient(
	t *testing.T,
	transport http.RoundTripper,
	limit int64,
) *Client {
	t.Helper()

	client, err := NewClient(
		authFuzzBaseURL,
		WithHTTPClient(&http.Client{Transport: transport}),
		WithBasicAuth(authFuzzUsername, authFuzzPassword),
		WithUserAgent(authFuzzUserAgent),
		WithRequestTimeout(fuzzResponseTimeout),
		WithMaxResponseBodySize(limit),
	)
	if err != nil {
		t.Fatalf("create auth fuzz client: %v", err)
	}

	return client
}

// authFuzzRedirectLocation selects a fixed relative redirect for one auth endpoint.
//
// Parameters:
//   - path: The original request path.
//
// Returns:
//   - location: A relative login or logout redirect target.
func authFuzzRedirectLocation(path string) string {
	if path == authFuzzLoginPath {
		return authFuzzLoginLocation
	}

	return authFuzzLogoutLocation
}

// requireAuthFuzzLoginRequest verifies the exact login request and JSON field presence.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - requests: The requests observed by the offline transport.
//   - bodies: The bounded request bodies observed by the offline transport.
//   - login: The expected login model.
func requireAuthFuzzLoginRequest(
	t *testing.T,
	requests []*http.Request,
	bodies [][]byte,
	login Login,
) {
	t.Helper()

	requireAuthFuzzSingleRequest(t, requests, bodies)
	requireAuthFuzzRequestMetadata(t, requests[0], http.MethodPost, authFuzzLoginPath)

	if requests[0].Header.Get("Content-Type") != jsonContentType {
		t.Fatalf("login content type = %q, want %q", requests[0].Header.Get("Content-Type"), jsonContentType)
	}

	var fields map[string]any

	err := json.Unmarshal(bodies[0], &fields)
	if err != nil {
		t.Fatalf("decode login request: %v", err)
	}

	requireAuthFuzzStringField(t, fields, "name", login.Name)
	requireAuthFuzzStringField(t, fields, "password", login.Password)
}

// requireAuthFuzzLogoutRequest verifies the exact bodyless logout request.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - requests: The requests observed by the offline transport.
//   - bodies: The bounded request bodies observed by the offline transport.
func requireAuthFuzzLogoutRequest(
	t *testing.T,
	requests []*http.Request,
	bodies [][]byte,
) {
	t.Helper()

	requireAuthFuzzSingleRequest(t, requests, bodies)
	requireAuthFuzzRequestMetadata(t, requests[0], http.MethodGet, authFuzzLogoutPath)

	if requests[0].Header.Get("Content-Type") != "" {
		t.Fatalf("logout content type = %q, want empty", requests[0].Header.Get("Content-Type"))
	}
	if len(bodies[0]) != 0 {
		t.Fatalf("logout body = %q, want empty", bodies[0])
	}
}

// requireAuthFuzzSingleRequest verifies that a redirect was not followed.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - requests: The requests observed by the offline transport.
//   - bodies: The bounded request bodies observed by the offline transport.
func requireAuthFuzzSingleRequest(
	t *testing.T,
	requests []*http.Request,
	bodies [][]byte,
) {
	t.Helper()

	if len(requests) != 1 || len(bodies) != 1 {
		t.Fatalf("auth request count = (%d, %d), want (1, 1)", len(requests), len(bodies))
	}
	if requests[0] == nil {
		t.Fatal("auth request is nil")
	}
}

// requireAuthFuzzRequestMetadata verifies common auth request headers and credentials.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - request: The captured auth request.
//   - method: The expected HTTP method.
//   - path: The expected endpoint path.
func requireAuthFuzzRequestMetadata(
	t *testing.T,
	request *http.Request,
	method string,
	path string,
) {
	t.Helper()

	if request.Method != method || request.URL.Path != path {
		t.Fatalf("auth request = (%q, %q), want (%q, %q)", request.Method, request.URL.Path, method, path)
	}
	if request.URL.RawQuery != "" {
		t.Fatalf("auth request query = %q, want empty", request.URL.RawQuery)
	}
	if request.Header.Get("Accept") != jsonContentType {
		t.Fatalf("auth accept = %q, want %q", request.Header.Get("Accept"), jsonContentType)
	}
	if request.Header.Get("User-Agent") != authFuzzUserAgent {
		t.Fatalf("auth user agent = %q, want %q", request.Header.Get("User-Agent"), authFuzzUserAgent)
	}

	username, password, authenticated := request.BasicAuth()
	if !authenticated || username != authFuzzUsername || password != authFuzzPassword {
		t.Fatalf("auth basic credentials = (%t, %q, %q)", authenticated, username, password)
	}
}

// requireAuthFuzzStringField verifies one optional JSON string member.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - fields: The decoded login request object.
//   - name: The JSON member name.
//   - expected: The expected optional string value.
func requireAuthFuzzStringField(
	t *testing.T,
	fields map[string]any,
	name string,
	expected string,
) {
	t.Helper()

	value, present := fields[name]
	if expected == "" {
		if present {
			t.Fatalf("login request unexpectedly contains %q: %#v", name, fields)
		}

		return
	}
	if !present || value != expected {
		t.Fatalf("login request %q = %#v, want %q", name, value, expected)
	}
}

// requireAuthFuzzLoginResult verifies login's empty-response and redirect policy.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by Login.
//   - statusCode: The deterministic response status.
//   - limit: The configured response-body limit.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func requireAuthFuzzLoginResult(
	t *testing.T,
	err error,
	statusCode int,
	limit int64,
	contentType string,
	body []byte,
) {
	t.Helper()

	switch {
	case authFuzzIsRedirect(statusCode):
		requireAuthFuzzRedirect(
			t,
			err,
			operationLogin,
			http.MethodPost,
			authFuzzRedirectBase+authFuzzLoginLocation,
		)
	case int64(len(body)) > limit:
		requireAuthFuzzTooLarge(
			t,
			err,
			statusCode,
			contentType,
			operationLogin,
			http.MethodPost,
			limit,
		)
	case authFuzzIsStatusFailure(statusCode):
		clientErr := requireAuthFuzzError(t, err, ErrorKindStatus, operationLogin, http.MethodPost)
		requireAuthFuzzStatusMetadata(t, clientErr, statusCode, contentType, body)
	default:
		requireAuthFuzzNoError(t, err, operationLogin)
	}
}

// requireAuthFuzzLogoutResult verifies logout's accepted redirect and status policy.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by Logout.
//   - statusCode: The deterministic response status.
//   - limit: The configured response-body limit.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func requireAuthFuzzLogoutResult(
	t *testing.T,
	err error,
	statusCode int,
	limit int64,
	contentType string,
	body []byte,
) {
	t.Helper()

	switch {
	case int64(len(body)) > limit:
		requireAuthFuzzTooLarge(
			t,
			err,
			statusCode,
			contentType,
			operationLogout,
			http.MethodGet,
			limit,
		)
	case statusCode == http.StatusFound:
		requireAuthFuzzNoError(t, err, operationLogout)
	case authFuzzIsRedirect(statusCode):
		requireAuthFuzzRedirect(
			t,
			err,
			operationLogout,
			http.MethodGet,
			authFuzzLogoutLocation,
		)
	default:
		clientErr := requireAuthFuzzError(t, err, ErrorKindStatus, operationLogout, http.MethodGet)
		requireAuthFuzzStatusMetadata(t, clientErr, statusCode, contentType, body)
	}
}

// authFuzzIsRedirect reports whether one status is in the redirect range.
//
// Parameters:
//   - statusCode: The deterministic response status.
//
// Returns:
//   - redirect: Whether the status is a redirect.
func authFuzzIsRedirect(statusCode int) bool {
	return statusCode >= http.StatusMultipleChoices && statusCode < http.StatusBadRequest
}

// authFuzzIsStatusFailure reports whether one status is outside the success range.
//
// Parameters:
//   - statusCode: The deterministic response status.
//
// Returns:
//   - failure: Whether the status requires structured status validation.
func authFuzzIsStatusFailure(statusCode int) bool {
	return statusCode < http.StatusOK || statusCode >= http.StatusMultipleChoices
}

// requireAuthFuzzRedirect verifies one rejected redirect.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by the auth operation.
//   - operation: The expected auth operation name.
//   - method: The expected HTTP method.
//   - location: The expected redirect location.
func requireAuthFuzzRedirect(
	t *testing.T,
	err error,
	operation string,
	method string,
	location string,
) {
	t.Helper()

	clientErr := requireAuthFuzzError(t, err, ErrorKindRedirect, operation, method)
	if clientErr.Location != location {
		t.Fatalf("auth redirect = %q, want %q", clientErr.Location, location)
	}
	if clientErr.Err == nil {
		t.Fatal("auth redirect error has no cause")
	}
}

// requireAuthFuzzNoError verifies one accepted auth response.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by the auth operation.
//   - operation: The accepted auth operation name.
func requireAuthFuzzNoError(t *testing.T, err error, operation string) {
	t.Helper()

	if err != nil {
		t.Fatalf("auth operation %q returned an unexpected error: %T %v", operation, err, err)
	}
}

// requireAuthFuzzTooLarge verifies one bounded-response error.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by the auth operation.
//   - statusCode: The deterministic response status.
//   - contentType: The deterministic response media type.
//   - operation: The expected auth operation name.
//   - method: The expected HTTP method.
//   - limit: The configured response-body limit.
func requireAuthFuzzTooLarge(
	t *testing.T,
	err error,
	statusCode int,
	contentType string,
	operation string,
	method string,
	limit int64,
) {
	t.Helper()

	clientErr := requireAuthFuzzError(t, err, ErrorKindResponseTooLarge, operation, method)
	if clientErr.StatusCode != statusCode || clientErr.ContentType != contentType {
		t.Fatalf(
			"auth response metadata = (%d, %q), want (%d, %q)",
			clientErr.StatusCode,
			clientErr.ContentType,
			statusCode,
			contentType,
		)
	}
	if clientErr.Limit != limit || clientErr.Body != nil {
		t.Fatalf(
			"auth size error = (limit %d, body %d), want (limit %d, body nil)",
			clientErr.Limit,
			len(clientErr.Body),
			limit,
		)
	}
}

// requireAuthFuzzStatusMetadata verifies one non-success response error.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - clientErr: The structured auth error.
//   - statusCode: The deterministic response status.
//   - contentType: The deterministic response media type.
//   - body: The bounded opaque response body.
func requireAuthFuzzStatusMetadata(
	t *testing.T,
	clientErr *Error,
	statusCode int,
	contentType string,
	body []byte,
) {
	t.Helper()

	if clientErr.StatusCode != statusCode || clientErr.ContentType != contentType {
		t.Fatalf(
			"auth response metadata = (%d, %q), want (%d, %q)",
			clientErr.StatusCode,
			clientErr.ContentType,
			statusCode,
			contentType,
		)
	}
	if !bytes.Equal(clientErr.Body, body) {
		t.Fatalf("auth response body = %q, want %q", clientErr.Body, body)
	}
	if clientErr.Err != nil {
		t.Fatalf("auth status error has cause %T %v", clientErr.Err, clientErr.Err)
	}
}

// requireAuthFuzzError verifies one structured auth error classification.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error to inspect.
//   - kind: The expected error classification.
//   - operation: The expected auth operation name.
//   - method: The expected HTTP method.
//
// Returns:
//   - clientErr: The extracted structured auth error.
func requireAuthFuzzError(
	t *testing.T,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	if !ok || clientErr == nil {
		t.Fatalf("auth error is not structured: %T %v", err, err)
	}
	if clientErr.Kind != kind || clientErr.Operation != operation || clientErr.Method != method {
		t.Fatalf(
			"auth error metadata = (%q, %q, %q), want (%q, %q, %q)",
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
