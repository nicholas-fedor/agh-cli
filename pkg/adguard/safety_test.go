// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// safetyRequestContract describes one safety request contract case.
type safetyRequestContract struct {
	// name is the subtest name.
	name string
	// method is the expected HTTP method.
	method string
	// path is the expected API path.
	path string
	// wantBody is the expected JSON request body, or an empty string for no body.
	wantBody string
	// responseBody is the response body returned by the test server.
	responseBody string
	// call invokes the safety operation under test.
	call func(context.Context, *Client) error
}

// safetyCapturedRequest contains request metadata captured by the safety test
// server.
type safetyCapturedRequest struct {
	// body is the received request body.
	body []byte
	// contentType is the request Content-Type header.
	contentType string
	// method is the received HTTP method.
	method string
	// path is the received API path.
	path string
	// query is the received encoded query string.
	query string
	// username is the received Basic Auth username.
	username string
	// password is the received Basic Auth password.
	password string
	// hasAuth reports whether Basic Auth was present.
	hasAuth bool
}

// safetyCall invokes one safety operation and returns its error.
type safetyCall func(context.Context, *Client) error

// safetyStatusCall describes one safety status read used by error tests.
type safetyStatusCall struct {
	// name is the subtest name.
	name string
	// call invokes the status operation under test.
	call safetyCall
}

const (
	// The absent name labels the absent-field test case.
	safetyAbsentName = "absent"
	// The false name labels the explicit-false test case.
	safetyFalseName = "false"
	// The true name labels the explicit-true test case.
	safetyTrueName = "true"
	// The enabled key is the enabled JSON field name.
	safetyEnabledKey = "enabled"
	// The Bing key is the Bing provider JSON field name.
	safetyBingKey = "bing"
	// The DuckDuckGo key is the DuckDuckGo provider JSON field name.
	safetyDuckDuckGoKey = "duckduckgo"
	// The Ecosia key is the Ecosia provider JSON field name.
	safetyEcosiaKey = "ecosia"
	// The Google key is the Google provider JSON field name.
	safetyGoogleKey = "google"
	// The Pixabay key is the Pixabay provider JSON field name.
	safetyPixabayKey = "pixabay"
	// The Yandex key is the Yandex provider JSON field name.
	safetyYandexKey = "yandex"
	// The YouTube key is the YouTube provider JSON field name.
	safetyYouTubeKey = "youtube"
	// The enabled null JSON is a response with a null enabled field.
	safetyEnabledNullJSON = `{"enabled":null}`
	// The enabled false JSON is a response with an explicit false enabled field.
	safetyEnabledFalseJSON = `{"enabled":false}`
	// The enabled true JSON is a response with an explicit true enabled field.
	safetyEnabledTrueJSON = `{"enabled":true}`
	// The parental status JSON is the complete parental status response fixture.
	safetyParentalStatusJSON = `{"enabled":true,"sensitivity":13}`
	// The safe-search status JSON is the complete safe-search response fixture.
	safetySafeSearchStatusJSON = `{
		"enabled":true,
		"bing":false,
		"duckduckgo":true,
		"ecosia":false,
		"google":true,
		"pixabay":false,
		"yandex":true,
		"youtube":false
	}`
)

// TestSafetyRequestContract verifies every safety operation's HTTP contract.
func TestSafetyRequestContract(t *testing.T) {
	t.Parallel()

	tests := safetyRequestContracts()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testSafetyRequest(t, test)
		})
	}
}

// TestSafetyStatusResponseModels verifies the typed status responses.
func TestSafetyStatusResponseModels(t *testing.T) {
	t.Parallel()

	t.Run("safebrowsing", func(t *testing.T) {
		t.Parallel()

		client := newSafetyJSONTestClient(t, safetyEnabledTrueJSON)

		status, err := client.SafebrowsingStatus(t.Context())

		require.NoError(t, err)
		require.NotNil(t, status.Enabled)
		assert.True(t, *status.Enabled)
	})

	t.Run("parental", func(t *testing.T) {
		t.Parallel()

		client := newSafetyJSONTestClient(t, safetyParentalStatusJSON)

		status, err := client.ParentalStatus(t.Context())

		require.NoError(t, err)
		require.NotNil(t, status.Enabled)
		assert.True(t, *status.Enabled)
		require.NotNil(t, status.Sensitivity)
		assert.Equal(t, int64(13), *status.Sensitivity)
	})

	t.Run("safesearch", func(t *testing.T) {
		t.Parallel()

		client := newSafetyJSONTestClient(t, safetySafeSearchStatusJSON)

		status, err := client.SafesearchStatus(t.Context())

		require.NoError(t, err)
		assertSafeSearchValues(t, status, []bool{true, false, true, false, true, false, true, false})
	})
}

// TestSafetyStatusPresence verifies absent, null, false, and true response values.
func TestSafetyStatusPresence(t *testing.T) {
	t.Parallel()

	t.Run("safebrowsing", testSafetySafebrowsingPresence)
	t.Run("parental", testSafetyParentalPresence)
}

// TestSafeSearchStatusPresence verifies provider-field presence semantics.
func TestSafeSearchStatusPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *bool
	}{
		{name: safetyAbsentName, body: `{}`, want: nil},
		{
			name: testNullJSON,
			body: `{
				"enabled":null,"bing":null,"duckduckgo":null,"ecosia":null,
				"google":null,"pixabay":null,"yandex":null,"youtube":null
			}`,
			want: nil,
		},
		{
			name: safetyFalseName,
			body: `{
				"enabled":false,"bing":false,"duckduckgo":false,"ecosia":false,
				"google":false,"pixabay":false,"yandex":false,"youtube":false
			}`,
			want: new(false),
		},
		{
			name: safetyTrueName,
			body: `{
				"enabled":true,"bing":true,"duckduckgo":true,"ecosia":true,
				"google":true,"pixabay":true,"yandex":true,"youtube":true
			}`,
			want: new(true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newSafetyJSONTestClient(t, test.body)

			status, err := client.SafesearchStatus(t.Context())

			require.NoError(t, err)
			assertSafeSearchPresence(t, status, test.want)
		})
	}
}

// TestSafeSearchSettingsPresence verifies omitted properties and explicit false values.
func TestSafeSearchSettingsPresence(t *testing.T) {
	t.Parallel()

	falseValue := false
	trueValue := true
	tests := []struct {
		name     string
		config   SafeSearchConfig
		wantBody map[string]any
	}{
		{
			name: "omitted",
			config: SafeSearchConfig{
				Enabled: nil, Bing: nil, DuckDuckGo: nil, Ecosia: nil,
				Google: nil, Pixabay: nil, Yandex: nil, YouTube: nil,
			},
			wantBody: map[string]any{},
		},
		{
			name: "explicit false",
			config: SafeSearchConfig{
				Enabled: &falseValue, Bing: &falseValue, DuckDuckGo: &falseValue, Ecosia: &falseValue,
				Google: &falseValue, Pixabay: &falseValue, Yandex: &falseValue, YouTube: &falseValue,
			},
			wantBody: map[string]any{
				safetyEnabledKey: false, safetyBingKey: false, safetyDuckDuckGoKey: false, safetyEcosiaKey: false,
				safetyGoogleKey: false, safetyPixabayKey: false, safetyYandexKey: false, safetyYouTubeKey: false,
			},
		},
		{
			name: "explicit true",
			config: SafeSearchConfig{
				Enabled: &trueValue, Bing: &trueValue, DuckDuckGo: &trueValue, Ecosia: &trueValue,
				Google: &trueValue, Pixabay: &trueValue, Yandex: &trueValue, YouTube: &trueValue,
			},
			wantBody: map[string]any{
				safetyEnabledKey: true, safetyBingKey: true, safetyDuckDuckGoKey: true, safetyEcosiaKey: true,
				safetyGoogleKey: true, safetyPixabayKey: true, safetyYandexKey: true, safetyYouTubeKey: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server, captured := newSafetyRequestServer(t, "")
			client := newSafetyTestClient(t, server, 4096)

			err := client.SafesearchSettings(t.Context(), test.config)

			require.NoError(t, err)

			request := <-captured
			var body map[string]any

			err = json.Unmarshal(request.body, &body)
			require.NoError(t, err)
			assert.Equal(t, test.wantBody, body)
		})
	}
}

// TestSafetyRejectsMalformedJSON verifies strict status response decoding.
func TestSafetyRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	tests := safetyStatusCalls()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyResponseServer(t, "application/json", `{"enabled":`)
			client := newSafetyTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindJSON)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestSafetyRejectsWrongContentType verifies JSON media type enforcement.
func TestSafetyRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	tests := safetyStatusCalls()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyResponseServer(t, "text/plain", safetyEnabledTrueJSON)
			client := newSafetyTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindContentType)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestSafetyRejectsNonSuccessResponses verifies status and method metadata.
func TestSafetyRejectsNonSuccessResponses(t *testing.T) {
	t.Parallel()

	tests := safetyRequestContracts()
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusTeapot)
				writeBody(w, "not available")
			}))
			client := newSafetyTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindStatus)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusTeapot, clientErr.StatusCode)
			assert.Equal(t, "not available", string(clientErr.Body))
		})
	}
}

// TestSafetyEnforcesResponseLimits verifies JSON and empty-success response bounds.
func TestSafetyEnforcesResponseLimits(t *testing.T) {
	t.Parallel()

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()

		server := newSafetyResponseServer(t, "application/json", safetyEnabledTrueJSON)
		client := newSafetyTestClient(t, server, int64(len(safetyEnabledTrueJSON))-1)

		_, err := client.SafebrowsingStatus(t.Context())

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, http.MethodGet, clientErr.Method)
		assert.Equal(t, int64(len(safetyEnabledTrueJSON))-1, clientErr.Limit)
	})

	tests := []struct {
		name   string
		method string
		call   func(context.Context, *Client) error
	}{
		{
			name:   "empty POST",
			method: http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				return client.SafebrowsingEnable(ctx)
			},
		},
		{
			name:   "empty PUT",
			method: http.MethodPut,
			call: func(ctx context.Context, client *Client) error {
				return client.SafesearchSettings(ctx, SafeSearchConfig{
					Enabled: nil, Bing: nil, DuckDuckGo: nil, Ecosia: nil,
					Google: nil, Pixabay: nil, Yandex: nil, YouTube: nil,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyResponseServer(t, "text/plain", "unexpected")
			client := newSafetyTestClient(t, server, 4)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, int64(4), clientErr.Limit)
		})
	}
}

// TestSafetyHonorsCancellation verifies cancellation for GET, POST, and PUT.
func TestSafetyHonorsCancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		call   func(context.Context, *Client) error
	}{
		{
			name:   "GET",
			method: http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.SafebrowsingStatus(ctx)

				return err
			},
		},
		{
			name:   "POST",
			method: http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				return client.ParentalDisable(ctx)
			},
		},
		{
			name:   "PUT",
			method: http.MethodPut,
			call: func(ctx context.Context, client *Client) error {
				return client.SafesearchSettings(ctx, SafeSearchConfig{
					Enabled: nil, Bing: nil, DuckDuckGo: nil, Ecosia: nil,
					Google: nil, Pixabay: nil, Yandex: nil, YouTube: nil,
				})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			client := newSafetyTestClient(t, server, 4096)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			err := test.call(ctx, client)

			clientErr := requireClientError(t, err, ErrorKindRequest)
			assert.Equal(t, test.method, clientErr.Method)
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

// safetyRequestContracts returns all safety request contracts.
//
// Returns:
//   - contracts: The complete safe-browsing, parental, and safe-search cases.
func safetyRequestContracts() []safetyRequestContract {
	return slices.Concat(
		safetySafebrowsingContracts(),
		safetyParentalContracts(),
		safetySafesearchContracts(),
	)
}

// safetySafebrowsingContracts returns safe-browsing request contracts.
//
// Returns:
//   - contracts: The enable, disable, and status cases.
func safetySafebrowsingContracts() []safetyRequestContract {
	return []safetyRequestContract{
		{
			name:         "safebrowsing enable",
			method:       http.MethodPost,
			path:         "/api/control/safebrowsing/enable",
			wantBody:     "",
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SafebrowsingEnable(ctx)
			},
		},
		{
			name:         "safebrowsing disable",
			method:       http.MethodPost,
			path:         "/api/control/safebrowsing/disable",
			wantBody:     "",
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SafebrowsingDisable(ctx)
			},
		},
		{
			name:         "safebrowsing status",
			method:       http.MethodGet,
			path:         "/api/control/safebrowsing/status",
			wantBody:     "",
			responseBody: safetyEnabledTrueJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.SafebrowsingStatus(ctx)

				return err
			},
		},
	}
}

// safetyParentalContracts returns parental-control request contracts.
//
// Returns:
//   - contracts: The enable, disable, and status cases.
func safetyParentalContracts() []safetyRequestContract {
	return []safetyRequestContract{
		{
			name:         "parental enable",
			method:       http.MethodPost,
			path:         "/api/control/parental/enable",
			wantBody:     "",
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.ParentalEnable(ctx)
			},
		},
		{
			name:         "parental disable",
			method:       http.MethodPost,
			path:         "/api/control/parental/disable",
			wantBody:     "",
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.ParentalDisable(ctx)
			},
		},
		{
			name:         "parental status",
			method:       http.MethodGet,
			path:         "/api/control/parental/status",
			wantBody:     "",
			responseBody: safetyParentalStatusJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.ParentalStatus(ctx)

				return err
			},
		},
	}
}

// safetySafesearchContracts returns safe-search request contracts.
//
// Returns:
//   - contracts: The settings and status cases.
func safetySafesearchContracts() []safetyRequestContract {
	falseValue := false
	trueValue := true

	return []safetyRequestContract{
		{
			name:   "safesearch settings",
			method: http.MethodPut,
			path:   "/api/control/safesearch/settings",
			wantBody: `{
				"enabled":false,"bing":false,"duckduckgo":true,"ecosia":false,
				"google":true,"pixabay":false,"yandex":true,"youtube":false
			}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SafesearchSettings(ctx, SafeSearchConfig{
					Enabled: &falseValue, Bing: &falseValue, DuckDuckGo: &trueValue, Ecosia: &falseValue,
					Google: &trueValue, Pixabay: &falseValue, Yandex: &trueValue, YouTube: &falseValue,
				})
			},
		},
		{
			name:         "safesearch status",
			method:       http.MethodGet,
			path:         "/api/control/safesearch/status",
			wantBody:     "",
			responseBody: safetySafeSearchStatusJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.SafesearchStatus(ctx)

				return err
			},
		},
	}
}

// safetyStatusCalls returns all safety status read operations.
//
// Returns:
//   - calls: The safe-browsing, parental, and safe-search status cases.
func safetyStatusCalls() []safetyStatusCall {
	return []safetyStatusCall{
		{
			name: "safebrowsing",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.SafebrowsingStatus(ctx)

				return err
			},
		},
		{
			name: "parental",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.ParentalStatus(ctx)

				return err
			},
		},
		{
			name: "safesearch",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.SafesearchStatus(ctx)

				return err
			},
		},
	}
}

// testSafetyRequest verifies one safety request contract.
//
// Parameters:
//   - test: The request contract to exercise.
func testSafetyRequest(t *testing.T, test safetyRequestContract) {
	t.Helper()

	server, captured := newSafetyRequestServer(t, test.responseBody)
	client := newSafetyTestClient(t, server, 4096)

	err := test.call(t.Context(), client)

	require.NoError(t, err)

	request := <-captured
	assert.Equal(t, test.method, request.method)
	assert.Equal(t, test.path, request.path)
	assert.Empty(t, request.query)
	assert.True(t, request.hasAuth)
	assert.Equal(t, "safety-user", request.username)
	assert.Equal(t, "safety-password", request.password)

	if test.method == http.MethodPut {
		assert.Equal(t, "application/json", request.contentType)
	} else {
		assert.Empty(t, request.contentType)
	}
	if test.wantBody == "" {
		assert.Empty(t, request.body)
	} else {
		assert.JSONEq(t, test.wantBody, string(request.body))
	}
}

// newSafetyRequestServer creates a server that captures one safety request.
//
// Parameters:
//   - responseBody: The response body returned after capturing the request.
//
// Returns:
//   - server: The HTTP test server.
//   - captured: A channel containing the captured request metadata.
func newSafetyRequestServer(
	t *testing.T,
	responseBody string,
) (*httptest.Server, <-chan safetyCapturedRequest) {
	t.Helper()

	captured := make(chan safetyCapturedRequest, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			err = r.Body.Close()
		}
		if err != nil {
			return
		}

		username, password, hasAuth := r.BasicAuth()
		captured <- safetyCapturedRequest{
			body:        body,
			contentType: r.Header.Get("Content-Type"),
			method:      r.Method,
			path:        r.URL.Path,
			query:       r.URL.RawQuery,
			username:    username,
			password:    password,
			hasAuth:     hasAuth,
		}

		if responseBody != "" {
			w.Header().Set("Content-Type", "application/json")
		}

		writeBody(w, responseBody)
	}))

	return server, captured
}

// newSafetyResponseServer creates a server that returns a fixed response.
//
// Parameters:
//   - contentType: The response Content-Type header.
//   - body: The response body.
//
// Returns:
//   - server: The HTTP test server.
func newSafetyResponseServer(t *testing.T, contentType, body string) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		writeBody(w, body)
	}))
}

// newSafetyJSONTestClient creates a client bound to a fixed JSON response server.
//
// Parameters:
//   - body: The JSON response body.
//
// Returns:
//   - client: The configured AdGuard client.
func newSafetyJSONTestClient(t *testing.T, body string) *Client {
	t.Helper()

	server := newSafetyResponseServer(t, "application/json", body)

	return newSafetyTestClient(t, server, int64(len(body)))
}

// newSafetyTestClient creates a client bound to a safety test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newSafetyTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth("safety-user", "safety-password"),
		WithUserAgent("adguard-safety-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// testSafetySafebrowsingPresence verifies safe-browsing enabled presence semantics.
func testSafetySafebrowsingPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *bool
	}{
		{name: safetyAbsentName, body: `{}`, want: nil},
		{name: testNullJSON, body: safetyEnabledNullJSON, want: nil},
		{name: safetyFalseName, body: safetyEnabledFalseJSON, want: new(false)},
		{name: safetyTrueName, body: safetyEnabledTrueJSON, want: new(true)},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			client := newSafetyJSONTestClient(t, testCase.body)
			status, err := client.SafebrowsingStatus(t.Context())

			require.NoError(t, err)
			assertOptionalBool(t, status.Enabled, testCase.want)
		})
	}
}

// testSafetyParentalPresence verifies parental status field presence semantics.
func testSafetyParentalPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		wantEnabled *bool
		wantLevel   *int64
	}{
		{name: safetyAbsentName, body: `{}`, wantEnabled: nil, wantLevel: nil},
		{
			name:        testNullJSON,
			body:        `{"enabled":null,"sensitivity":null}`,
			wantEnabled: nil,
			wantLevel:   nil,
		},
		{
			name:        "false and zero",
			body:        `{"enabled":false,"sensitivity":0}`,
			wantEnabled: new(false),
			wantLevel:   new(int64(0)),
		},
		{
			name:        safetyTrueName,
			body:        `{"enabled":true,"sensitivity":13}`,
			wantEnabled: new(true),
			wantLevel:   new(int64(13)),
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			client := newSafetyJSONTestClient(t, testCase.body)
			status, err := client.ParentalStatus(t.Context())

			require.NoError(t, err)
			assertOptionalBool(t, status.Enabled, testCase.wantEnabled)
			assertOptionalInt64(t, status.Sensitivity, testCase.wantLevel)
		})
	}
}

// assertOptionalBool verifies an optional boolean response value.
//
// Parameters:
//   - got: The decoded pointer to inspect.
//   - want: The expected pointer value.
func assertOptionalBool(t *testing.T, got, want *bool) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got)

		return
	}

	require.NotNil(t, got)
	assert.Equal(t, *want, *got)
}

// assertOptionalInt64 verifies an optional int64 response value.
//
// Parameters:
//   - got: The decoded pointer to inspect.
//   - want: The expected pointer value.
func assertOptionalInt64(t *testing.T, got, want *int64) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got)

		return
	}

	require.NotNil(t, got)
	assert.Equal(t, *want, *got)
}

// assertSafeSearchPresence verifies the same expected value across all providers.
//
// Parameters:
//   - config: The decoded safe-search configuration to inspect.
//   - want: The expected pointer value for every provider field.
func assertSafeSearchPresence(t *testing.T, config *SafeSearchConfig, want *bool) {
	t.Helper()

	values := []*bool{
		config.Enabled, config.Bing, config.DuckDuckGo, config.Ecosia,
		config.Google, config.Pixabay, config.Yandex, config.YouTube,
	}
	if want == nil {
		for _, value := range values {
			assert.Nil(t, value)
		}

		return
	}

	for _, value := range values {
		require.NotNil(t, value)
		assert.Equal(t, *want, *value)
	}
}

// assertSafeSearchValues verifies the decoded provider values in field order.
//
// Parameters:
//   - config: The decoded safe-search configuration to inspect.
//   - want: The expected provider values in field order.
func assertSafeSearchValues(t *testing.T, config *SafeSearchConfig, want []bool) {
	t.Helper()

	values := []*bool{
		config.Enabled, config.Bing, config.DuckDuckGo, config.Ecosia,
		config.Google, config.Pixabay, config.Yandex, config.YouTube,
	}
	require.Len(t, values, len(want))

	for index, value := range values {
		require.NotNil(t, value)
		assert.Equal(t, want[index], *value)
	}
}
