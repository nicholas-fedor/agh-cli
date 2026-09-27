// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// safetyIntegrationRequestCapture contains the request metadata observed by a
// safety integration server.
type safetyIntegrationRequestCapture struct {
	// accept is the request Accept header.
	accept string
	// body is the request body.
	body []byte
	// contentType is the request Content-Type header.
	contentType string
	// hasAuth reports whether the request contains Basic Auth credentials.
	hasAuth bool
	// method is the request HTTP method.
	method string
	// path is the request URL path.
	path string
	// password is the Basic Auth password.
	password string
	// query is the request URL query.
	query string
	// readErr is the error encountered while reading the request body.
	readErr error
	// userAgent is the request User-Agent header.
	userAgent string
	// username is the Basic Auth username.
	username string
}

// safetyIntegrationOperationCase describes one successful safety operation
// request contract.
type safetyIntegrationOperationCase struct {
	// call invokes the operation under test.
	call func(context.Context, *adguard.Client) error
	// expectedBody is the decoded JSON request body, or nil when no body is sent.
	expectedBody map[string]any
	// method is the expected HTTP method.
	method string
	// name identifies the subtest.
	name string
	// operation is the public operation identifier used by structured errors.
	operation string
	// path is the expected API path.
	path string
	// responseBody is the successful response body.
	responseBody string
	// responseContentType is the successful response media type, if any.
	responseContentType string
}

// safetyIntegrationStatusCall describes one safety status operation.
type safetyIntegrationStatusCall struct {
	// call invokes the status operation under test.
	call func(context.Context, *adguard.Client) error
	// method is the expected HTTP method.
	method string
	// name identifies the subtest.
	name string
	// operation is the public operation identifier used by structured errors.
	operation string
}

// safetyIntegrationResponseErrorCase describes one invalid safety response.
type safetyIntegrationResponseErrorCase struct {
	// body is the response body returned by the test server.
	body string
	// contentType is the response media type returned by the test server.
	contentType string
	// kind is the expected structured error kind.
	kind adguard.ErrorKind
	// name identifies the subtest.
	name string
	// wantContentType is the expected structured error media type.
	wantContentType string
}

const (
	// The shared enabled false JSON is a response with an explicit false enabled field.
	integrationEnabledFalseJSON = `{"enabled":false}`
	// Safety integration username is the Basic Auth username used by safety tests.
	safetyIntegrationUsername = "safety-user"
	// Safety integration password is the Basic Auth password used by safety tests.
	safetyIntegrationPassword = "safety-password"
	// Safety integration user agent is the User-Agent used by safety tests.
	safetyIntegrationUserAgent = "agh-cli-safety-integration-test/1.0"
	// Safety integration accepted response body is a JSON mutation response fixture.
	safetyIntegrationAcceptedResponseBody = `{"accepted":true}`
	// Safety integration response limit is the ordinary response limit for safety tests.
	safetyIntegrationResponseLimit = int64(4096)
	// Safety integration absent name labels an omitted response property.
	safetyIntegrationAbsentName = "absent"
	// Safety integration null name labels a null response property.
	safetyIntegrationNullName = "null"
	// Safety integration false name labels an explicit false response value.
	safetyIntegrationFalseName = "false"
	// Safety integration true name labels an explicit true response value.
	safetyIntegrationTrueName = "true"
	// Safety integration malformed name labels a malformed JSON response case.
	safetyIntegrationMalformedName = "malformed JSON"
	// Safety integration enabled key is the common enabled JSON property name.
	safetyIntegrationEnabledKey = "enabled"
	// Safety integration Bing key is the Bing provider JSON property name.
	safetyIntegrationBingKey = "bing"
	// Safety integration DuckDuckGo key is the DuckDuckGo provider JSON property name.
	safetyIntegrationDuckDuckGoKey = "duckduckgo"
	// Safety integration Ecosia key is the Ecosia provider JSON property name.
	safetyIntegrationEcosiaKey = "ecosia"
	// Safety integration Google key is the Google provider JSON property name.
	safetyIntegrationGoogleKey = "google"
	// Safety integration Pixabay key is the Pixabay provider JSON property name.
	safetyIntegrationPixabayKey = "pixabay"
	// Safety integration Yandex key is the Yandex provider JSON property name.
	safetyIntegrationYandexKey = "yandex"
	// Safety integration YouTube key is the YouTube provider JSON property name.
	safetyIntegrationYouTubeKey = "youtube"
	// Safety integration safebrowsing status operation names the status error operation.
	safetyIntegrationSafebrowsingStatusOperation = "safebrowsing_status"
	// Safety integration safesearch settings operation names the settings error operation.
	safetyIntegrationSafesearchSettingsOperation = "safesearch_settings"
	// Safety integration parental status operation names the status error operation.
	safetyIntegrationParentalStatusOperation = "parental_status"
	// Safety integration safebrowsing enable operation names the enable error operation.
	safetyIntegrationSafebrowsingEnableOperation = "safebrowsing_enable"
	// Safety integration safebrowsing disable operation names the disable error operation.
	safetyIntegrationSafebrowsingDisableOperation = "safebrowsing_disable"
	// Safety integration parental enable operation names the enable error operation.
	safetyIntegrationParentalEnableOperation = "parental_enable"
	// Safety integration parental disable operation names the disable error operation.
	safetyIntegrationParentalDisableOperation = "parental_disable"
	// Safety integration safesearch status operation names the status error operation.
	safetyIntegrationSafesearchStatusOperation = "safesearch_status"
)

// TestSafetyIntegrationRequestContracts verifies every safety operation's HTTP contract.
func TestSafetyIntegrationRequestContracts(t *testing.T) {
	t.Parallel()

	for _, test := range safetyIntegrationOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server, captured := newSafetyIntegrationServer(
				t,
				test.responseContentType,
				test.responseBody,
			)
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

			err := test.call(t.Context(), client)
			require.NoError(t, err)

			assertSafetyIntegrationRequest(t, test, <-captured)
		})
	}
}

// TestSafetyIntegrationSafebrowsingPointerPresence verifies safe-browsing
// optional boolean decoding.
func TestSafetyIntegrationSafebrowsingPointerPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *bool
	}{
		{name: safetyIntegrationAbsentName, body: `{}`, want: nil},
		{name: safetyIntegrationNullName, body: `{"enabled":null}`, want: nil},
		{name: safetyIntegrationFalseName, body: integrationEnabledFalseJSON, want: new(false)},
		{name: safetyIntegrationTrueName, body: `{"enabled":true}`, want: new(true)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyIntegrationResponseServer(t, blockedServicesIntegrationJSONContentType, test.body, 0)
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

			status, err := client.SafebrowsingStatus(t.Context())

			require.NoError(t, err)
			require.NotNil(t, status)
			assertSafetyIntegrationOptionalBool(t, status.Enabled, test.want)
		})
	}
}

// TestSafetyIntegrationParentalPointerPresence verifies parental status pointer
// and zero-value decoding.
func TestSafetyIntegrationParentalPointerPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		body        string
		wantEnabled *bool
		wantLevel   *int64
	}{
		{name: safetyIntegrationAbsentName, body: `{}`, wantEnabled: nil, wantLevel: nil},
		{
			name:        safetyIntegrationNullName,
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
			name:        "true and value",
			body:        `{"enabled":true,"sensitivity":13}`,
			wantEnabled: new(true),
			wantLevel:   new(int64(13)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyIntegrationResponseServer(t, blockedServicesIntegrationJSONContentType, test.body, 0)
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

			status, err := client.ParentalStatus(t.Context())

			require.NoError(t, err)
			require.NotNil(t, status)
			assertSafetyIntegrationOptionalBool(t, status.Enabled, test.wantEnabled)
			assertSafetyIntegrationOptionalInt64(t, status.Sensitivity, test.wantLevel)
		})
	}
}

// TestSafetyIntegrationSafesearchPointerPresence verifies safe-search provider
// optional boolean decoding.
func TestSafetyIntegrationSafesearchPointerPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *bool
	}{
		{name: safetyIntegrationAbsentName, body: `{}`, want: nil},
		{
			name: safetyIntegrationNullName,
			body: `{
				"enabled":null,"bing":null,"duckduckgo":null,"ecosia":null,
				"google":null,"pixabay":null,"yandex":null,"youtube":null
			}`,
			want: nil,
		},
		{
			name: safetyIntegrationFalseName,
			body: `{
				"enabled":false,"bing":false,"duckduckgo":false,"ecosia":false,
				"google":false,"pixabay":false,"yandex":false,"youtube":false
			}`,
			want: new(false),
		},
		{
			name: safetyIntegrationTrueName,
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

			server := newSafetyIntegrationResponseServer(t, blockedServicesIntegrationJSONContentType, test.body, 0)
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

			status, err := client.SafesearchStatus(t.Context())

			require.NoError(t, err)
			require.NotNil(t, status)
			assertSafetyIntegrationSafeSearchPresence(t, status, test.want)
		})
	}
}

// TestSafetyIntegrationSafesearchSettingsPresence verifies omission and explicit
// boolean values in safe-search settings requests.
func TestSafetyIntegrationSafesearchSettingsPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		config adguard.SafeSearchConfig
		want   map[string]any
	}{
		{
			name:   "all fields omitted",
			config: adguard.SafeSearchConfig{},
			want:   map[string]any{},
		},
		{
			name: "explicit false",
			config: adguard.SafeSearchConfig{
				Enabled: new(false), Bing: new(false), DuckDuckGo: new(false), Ecosia: new(false),
				Google: new(false), Pixabay: new(false), Yandex: new(false), YouTube: new(false),
			},
			want: map[string]any{
				safetyIntegrationEnabledKey:    false,
				safetyIntegrationBingKey:       false,
				safetyIntegrationDuckDuckGoKey: false,
				safetyIntegrationEcosiaKey:     false,
				safetyIntegrationGoogleKey:     false,
				safetyIntegrationPixabayKey:    false,
				safetyIntegrationYandexKey:     false,
				safetyIntegrationYouTubeKey:    false,
			},
		},
		{
			name: "explicit true",
			config: adguard.SafeSearchConfig{
				Enabled: new(true), Bing: new(true), DuckDuckGo: new(true), Ecosia: new(true),
				Google: new(true), Pixabay: new(true), Yandex: new(true), YouTube: new(true),
			},
			want: map[string]any{
				safetyIntegrationEnabledKey:    true,
				safetyIntegrationBingKey:       true,
				safetyIntegrationDuckDuckGoKey: true,
				safetyIntegrationEcosiaKey:     true,
				safetyIntegrationGoogleKey:     true,
				safetyIntegrationPixabayKey:    true,
				safetyIntegrationYandexKey:     true,
				safetyIntegrationYouTubeKey:    true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server, captured := newSafetyIntegrationServer(t, "", "")
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

			err := client.SafesearchSettings(t.Context(), test.config)

			require.NoError(t, err)
			assertSafetyIntegrationJSONBody(t, test.want, <-captured)
		})
	}
}

// TestSafetyIntegrationStatusErrors verifies structured errors for every safety
// operation's non-success response.
func TestSafetyIntegrationStatusErrors(t *testing.T) {
	t.Parallel()

	for _, test := range safetyIntegrationOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyIntegrationResponseServer(
				t,
				filteringIntegrationTextMediaType,
				"safety failure",
				http.StatusTeapot,
			)
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

			err := test.call(t.Context(), client)

			clientErr := safetyIntegrationRequireError(t, err, adguard.ErrorKindStatus)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusTeapot, clientErr.StatusCode)
			assert.Equal(t, "418 I'm a teapot", clientErr.Status)
			assert.Equal(t, filteringIntegrationTextMediaType, clientErr.ContentType)
			assert.Equal(t, "safety failure", string(clientErr.Body))
		})
	}
}

// TestSafetyIntegrationStatusResponseErrors verifies JSON, media-type, and
// empty-response errors from all safety status operations.
func TestSafetyIntegrationStatusResponseErrors(t *testing.T) {
	t.Parallel()

	for _, operation := range safetyIntegrationStatusCalls() {
		for _, response := range safetyIntegrationStatusResponseErrorCases() {
			t.Run(operation.name+"/"+response.name, func(t *testing.T) {
				t.Parallel()

				runSafetyIntegrationStatusResponseError(t, operation, response)
			})
		}
	}
}

// TestSafetyIntegrationResponseLimitErrors verifies structured response-limit
// errors for status and mutation methods.
func TestSafetyIntegrationResponseLimitErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		call      func(context.Context, *adguard.Client) error
		method    string
		name      string
		operation string
	}{
		{
			name:      "status response",
			operation: safetyIntegrationSafebrowsingStatusOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.SafebrowsingStatus(ctx)

				return err
			},
		},
		{
			name:      "empty response",
			operation: safetyIntegrationSafebrowsingEnableOperation,
			method:    http.MethodPost,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SafebrowsingEnable(ctx)
			},
		},
		{
			name:      "settings response",
			operation: safetyIntegrationSafesearchSettingsOperation,
			method:    http.MethodPut,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SafesearchSettings(ctx, adguard.SafeSearchConfig{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyIntegrationResponseServer(
				t,
				blockedServicesIntegrationJSONContentType,
				"ignored",
				0,
			)
			client := newSafetyIntegrationClient(t, server, 1)

			err := test.call(t.Context(), client)

			clientErr := safetyIntegrationRequireError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, int64(1), clientErr.Limit)
		})
	}
}

// TestSafetyIntegrationCancellationErrors verifies structured cancellation
// errors for status, enable, and settings methods.
func TestSafetyIntegrationCancellationErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		call      func(context.Context, *adguard.Client) error
		method    string
		name      string
		operation string
	}{
		{
			name:      filteringIntegrationStatusName,
			operation: safetyIntegrationParentalStatusOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.ParentalStatus(ctx)

				return err
			},
		},
		{
			name:      "enable",
			operation: safetyIntegrationParentalEnableOperation,
			method:    http.MethodPost,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.ParentalEnable(ctx)
			},
		},
		{
			name:      "settings",
			operation: safetyIntegrationSafesearchSettingsOperation,
			method:    http.MethodPut,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SafesearchSettings(ctx, adguard.SafeSearchConfig{})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newSafetyIntegrationResponseServer(t, blockedServicesIntegrationJSONContentType, "{}", 0)
			client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			err := test.call(ctx, client)

			clientErr := safetyIntegrationRequireError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

// safetyIntegrationOperationCases returns every safety operation's successful
// request contract.
//
// Returns:
//   - contracts: The complete safe-browsing, parental, and safe-search cases.
func safetyIntegrationOperationCases() []safetyIntegrationOperationCase {
	return slices.Concat(
		safetyIntegrationSafebrowsingCases(),
		safetyIntegrationParentalCases(),
		safetyIntegrationSafesearchCases(),
	)
}

// safetyIntegrationSafebrowsingCases returns safe-browsing request contracts.
//
// Returns:
//   - contracts: The enable, disable, and status cases.
func safetyIntegrationSafebrowsingCases() []safetyIntegrationOperationCase {
	return []safetyIntegrationOperationCase{
		{
			name:         "safebrowsing enable",
			operation:    safetyIntegrationSafebrowsingEnableOperation,
			method:       http.MethodPost,
			path:         "/api/control/safebrowsing/enable",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SafebrowsingEnable(ctx)
			},
		},
		{
			name:                "safebrowsing disable",
			operation:           safetyIntegrationSafebrowsingDisableOperation,
			method:              http.MethodPost,
			path:                "/api/control/safebrowsing/disable",
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseBody:        safetyIntegrationAcceptedResponseBody,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SafebrowsingDisable(ctx)
			},
		},
		{
			name:                "safebrowsing status",
			operation:           safetyIntegrationSafebrowsingStatusOperation,
			method:              http.MethodGet,
			path:                "/api/control/safebrowsing/status",
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseBody:        integrationEnabledFalseJSON,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.SafebrowsingStatus(ctx)

				return err
			},
		},
	}
}

// safetyIntegrationParentalCases returns parental-control request contracts.
//
// Returns:
//   - contracts: The enable, disable, and status cases.
func safetyIntegrationParentalCases() []safetyIntegrationOperationCase {
	return []safetyIntegrationOperationCase{
		{
			name:         "parental enable",
			operation:    safetyIntegrationParentalEnableOperation,
			method:       http.MethodPost,
			path:         "/api/control/parental/enable",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.ParentalEnable(ctx)
			},
		},
		{
			name:                "parental disable",
			operation:           safetyIntegrationParentalDisableOperation,
			method:              http.MethodPost,
			path:                "/api/control/parental/disable",
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseBody:        safetyIntegrationAcceptedResponseBody,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.ParentalDisable(ctx)
			},
		},
		{
			name:                "parental status",
			operation:           safetyIntegrationParentalStatusOperation,
			method:              http.MethodGet,
			path:                "/api/control/parental/status",
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseBody:        `{"enabled":true,"sensitivity":13}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.ParentalStatus(ctx)

				return err
			},
		},
	}
}

// safetyIntegrationSafesearchCases returns safe-search request contracts.
//
// Returns:
//   - contracts: The settings and status cases.
func safetyIntegrationSafesearchCases() []safetyIntegrationOperationCase {
	return []safetyIntegrationOperationCase{
		{
			name:                "safesearch settings",
			operation:           safetyIntegrationSafesearchSettingsOperation,
			method:              http.MethodPut,
			path:                "/api/control/safesearch/settings",
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseBody:        safetyIntegrationAcceptedResponseBody,
			expectedBody: map[string]any{
				safetyIntegrationEnabledKey:    false,
				safetyIntegrationBingKey:       false,
				safetyIntegrationDuckDuckGoKey: true,
				safetyIntegrationEcosiaKey:     false,
				safetyIntegrationGoogleKey:     true,
				safetyIntegrationPixabayKey:    false,
				safetyIntegrationYandexKey:     true,
				safetyIntegrationYouTubeKey:    false,
			},
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SafesearchSettings(ctx, adguard.SafeSearchConfig{
					Enabled: new(false), Bing: new(false), DuckDuckGo: new(true), Ecosia: new(false),
					Google: new(true), Pixabay: new(false), Yandex: new(true), YouTube: new(false),
				})
			},
		},
		{
			name:                "safesearch status",
			operation:           safetyIntegrationSafesearchStatusOperation,
			method:              http.MethodGet,
			path:                "/api/control/safesearch/status",
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseBody: `{
				"enabled":true,"bing":false,"duckduckgo":true,"ecosia":false,
				"google":true,"pixabay":false,"yandex":true,"youtube":false
			}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.SafesearchStatus(ctx)

				return err
			},
		},
	}
}

// safetyIntegrationStatusCalls returns every safety status operation.
//
// Returns:
//   - calls: The safe-browsing, parental, and safe-search status cases.
func safetyIntegrationStatusCalls() []safetyIntegrationStatusCall {
	return []safetyIntegrationStatusCall{
		{
			name:      "safebrowsing",
			operation: safetyIntegrationSafebrowsingStatusOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.SafebrowsingStatus(ctx)

				return err
			},
		},
		{
			name:      "parental",
			operation: safetyIntegrationParentalStatusOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.ParentalStatus(ctx)

				return err
			},
		},
		{
			name:      "safesearch",
			operation: safetyIntegrationSafesearchStatusOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.SafesearchStatus(ctx)

				return err
			},
		},
	}
}

// safetyIntegrationStatusResponseErrorCases returns invalid safety responses.
//
// Returns:
//   - cases: The malformed, null, empty, and media-type response cases.
func safetyIntegrationStatusResponseErrorCases() []safetyIntegrationResponseErrorCase {
	return []safetyIntegrationResponseErrorCase{
		{
			name:        safetyIntegrationMalformedName,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        filteringIntegrationTruncatedJSON,
			kind:        adguard.ErrorKindJSON,
		},
		{
			name:        "top-level null",
			contentType: blockedServicesIntegrationJSONContentType,
			body:        safetyIntegrationNullName,
			kind:        adguard.ErrorKindJSON,
		},
		{
			name:        "empty JSON response",
			contentType: blockedServicesIntegrationJSONContentType,
			body:        "",
			kind:        adguard.ErrorKindJSON,
		},
		{
			name:            "wrong media type",
			contentType:     filteringIntegrationTextMediaType,
			body:            `{}`,
			kind:            adguard.ErrorKindContentType,
			wantContentType: filteringIntegrationTextMediaType,
		},
	}
}

// runSafetyIntegrationStatusResponseError verifies one invalid status response.
//
// Parameters:
//   - operation: The status operation to invoke.
//   - response: The invalid response to return.
func runSafetyIntegrationStatusResponseError(
	t *testing.T,
	operation safetyIntegrationStatusCall,
	response safetyIntegrationResponseErrorCase,
) {
	t.Helper()

	server := newSafetyIntegrationResponseServer(
		t,
		response.contentType,
		response.body,
		0,
	)
	client := newSafetyIntegrationClient(t, server, safetyIntegrationResponseLimit)

	err := operation.call(t.Context(), client)

	clientErr := safetyIntegrationRequireError(t, err, response.kind)
	assert.Equal(t, operation.operation, clientErr.Operation)
	assert.Equal(t, operation.method, clientErr.Method)
	require.Error(t, clientErr.Err)
	assert.Equal(t, response.wantContentType, clientErr.ContentType)
}

// newSafetyIntegrationServer creates a server that captures one safety request.
//
// Parameters:
//   - responseContentType: The successful response media type, if any.
//   - responseBody: The successful response body.
//
// Returns:
//   - server: The HTTP test server.
//   - captured: A channel containing the captured request metadata.
func newSafetyIntegrationServer(
	t *testing.T,
	responseContentType string,
	responseBody string,
) (*httptest.Server, <-chan safetyIntegrationRequestCapture) {
	t.Helper()

	captured := make(chan safetyIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, readErr := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if readErr == nil {
			readErr = closeErr
		}

		username, password, hasAuth := r.BasicAuth()
		captured <- safetyIntegrationRequestCapture{
			accept:      r.Header.Get("Accept"),
			body:        requestBody,
			contentType: r.Header.Get("Content-Type"),
			hasAuth:     hasAuth,
			method:      r.Method,
			path:        r.URL.Path,
			password:    password,
			query:       r.URL.RawQuery,
			readErr:     readErr,
			userAgent:   r.Header.Get("User-Agent"),
			username:    username,
		}

		if responseContentType != "" {
			w.Header().Set("Content-Type", responseContentType)
		}

		writeSafetyIntegrationBody(w, responseBody)
	}))

	return server, captured
}

// newSafetyIntegrationResponseServer creates a server that returns a fixed
// response without inspecting the request.
//
// Parameters:
//   - contentType: The response media type.
//   - body: The response body.
//   - statusCode: The response status code, or zero for the default status.
//
// Returns:
//   - server: The HTTP test server.
func newSafetyIntegrationResponseServer(
	t *testing.T,
	contentType string,
	body string,
	statusCode int,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)

		if statusCode != 0 {
			w.WriteHeader(statusCode)
		}

		writeSafetyIntegrationBody(w, body)
	}))
}

// newSafetyIntegrationClient creates a concrete client bound to a safety test
// server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newSafetyIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		blockedServicesIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(safetyIntegrationUsername, safetyIntegrationPassword),
		adguard.WithUserAgent(safetyIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// assertSafetyIntegrationRequest verifies the exact safety request contract.
//
// Parameters:
//   - test: The request contract to inspect.
//   - request: The captured request metadata.
func assertSafetyIntegrationRequest(
	t *testing.T,
	test safetyIntegrationOperationCase,
	request safetyIntegrationRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	assert.Equal(t, test.method, request.method)
	assert.Equal(t, test.path, request.path)
	assert.Empty(t, request.query)
	assert.Equal(t, "application/json", request.accept)
	assert.Equal(t, safetyIntegrationUserAgent, request.userAgent)
	assert.True(t, request.hasAuth)
	assert.Equal(t, safetyIntegrationUsername, request.username)
	assert.Equal(t, safetyIntegrationPassword, request.password)

	if test.method == http.MethodPut {
		assert.Equal(t, "application/json", request.contentType)
	} else {
		assert.Empty(t, request.contentType)
	}

	if test.expectedBody == nil {
		assert.Empty(t, request.body)

		return
	}

	assertSafetyIntegrationJSONBody(t, test.expectedBody, request)
}

// assertSafetyIntegrationJSONBody verifies the decoded JSON request body.
//
// Parameters:
//   - want: The expected decoded request object.
//   - request: The captured request metadata.
func assertSafetyIntegrationJSONBody(
	t *testing.T,
	want map[string]any,
	request safetyIntegrationRequestCapture,
) {
	t.Helper()

	var body map[string]any

	require.NoError(t, json.Unmarshal(request.body, &body))
	assert.Equal(t, want, body)
}

// safetyIntegrationRequireError extracts and verifies a structured client error.
//
// Parameters:
//   - err: The operation error to inspect.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func safetyIntegrationRequireError(
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

// assertSafetyIntegrationOptionalBool verifies an optional boolean value.
//
// Parameters:
//   - got: The decoded pointer to inspect.
//   - want: The expected pointer value.
func assertSafetyIntegrationOptionalBool(t *testing.T, got, want *bool) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got)

		return
	}

	require.NotNil(t, got)
	assert.Equal(t, *want, *got)
}

// assertSafetyIntegrationOptionalInt64 verifies an optional int64 value.
//
// Parameters:
//   - got: The decoded pointer to inspect.
//   - want: The expected pointer value.
func assertSafetyIntegrationOptionalInt64(t *testing.T, got, want *int64) {
	t.Helper()

	if want == nil {
		assert.Nil(t, got)

		return
	}

	require.NotNil(t, got)
	assert.Equal(t, *want, *got)
}

// assertSafetyIntegrationSafeSearchPresence verifies every safe-search provider
// pointer against one expected value.
//
// Parameters:
//   - config: The decoded safe-search configuration to inspect.
//   - want: The expected pointer value for every provider field.
func assertSafetyIntegrationSafeSearchPresence(
	t *testing.T,
	config *adguard.SafeSearchConfig,
	want *bool,
) {
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

// writeSafetyIntegrationBody writes a response body while tolerating client
// disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeSafetyIntegrationBody(w http.ResponseWriter, body string) {
	if body == "" {
		return
	}

	_, err := w.Write([]byte(body))
	if err != nil {
		return
	}
}
