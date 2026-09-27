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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// deprecatedOperationCase describes one deprecated operation contract.
type deprecatedOperationCase struct {
	call                deprecatedCall
	method              string
	name                string
	operation           string
	path                string
	requestBody         string
	responseBody        string
	responseContentType string
	verify              func(*testing.T, any)
}

// deprecatedCall invokes one client operation for table tests.
type deprecatedCall func(context.Context, *adguard.Client) (any, error)

// deprecatedRequestCapture records one received HTTP request.
type deprecatedRequestCapture struct {
	accept        string
	body          []byte
	contentLength int64
	contentType   string
	hasAuth       bool
	method        string
	password      string
	path          string
	query         string
	readErr       error
	userAgent     string
	username      string
}

// deprecatedResponseErrorCase describes one legacy response failure.
type deprecatedResponseErrorCase struct {
	body            string
	call            deprecatedCall
	contentType     string
	kind            adguard.ErrorKind
	method          string
	name            string
	operation       string
	wantContentType string
}

const (
	// The deprecatedTestBaseURL constant is routed by the in-memory transport.
	deprecatedTestBaseURL = "http://127.0.0.1"
	// The deprecatedTestUsername constant is the expected Basic authentication username.
	deprecatedTestUsername = "deprecated-user"
	// The deprecatedTestPassword constant is the expected Basic authentication password.
	deprecatedTestPassword = "deprecated-password"
	// The deprecatedTestUserAgent constant is the expected client User-Agent.
	deprecatedTestUserAgent = "agh-cli-deprecated-test/1.0"
	// The deprecatedJSONMediaType constant is the successful JSON response media type.
	deprecatedJSONMediaType = "application/json"
	// The deprecatedProblemMediaType constant is the structured error response media type.
	deprecatedProblemMediaType = "application/problem+json"
	// The deprecatedResponseLimit constant is the normal response-body limit.
	deprecatedResponseLimit = int64(4096)
	// The deprecatedRequestTimeout constant bounds every test request.
	deprecatedRequestTimeout = time.Second
	// The deprecatedStatusBody constant is the bounded structured error payload.
	deprecatedStatusBody = `{"message":"deprecated operation rejected"}`
)

// TestDeprecatedCompatibilityRequestContracts verifies every deprecated HTTP
// method, path, body, response, and result contract.
func TestDeprecatedCompatibilityRequestContracts(t *testing.T) {
	t.Parallel()

	tests := deprecatedOperationCases()
	for index := range tests {
		test := &tests[index]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan deprecatedRequestCapture, 1)
			server := newDeprecatedCapturingServer(
				t,
				http.StatusOK,
				test.responseContentType,
				test.responseBody,
				captured,
			)
			client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

			result, err := test.call(t.Context(), client)

			require.NoError(t, err)

			assertDeprecatedRequest(t, *test, <-captured)

			if test.verify != nil {
				test.verify(t, result)
			}
		})
	}
}

// TestDeprecatedCompatibilityStatusErrors verifies structured HTTP failures for
// every deprecated operation.
func TestDeprecatedCompatibilityStatusErrors(t *testing.T) {
	t.Parallel()

	tests := deprecatedOperationCases()
	for index := range tests {
		test := &tests[index]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newDeprecatedResponseServer(
				t,
				http.StatusServiceUnavailable,
				deprecatedProblemMediaType,
				deprecatedStatusBody,
			)
			client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

			_, err := test.call(t.Context(), client)

			clientErr := requireDeprecatedError(t, err, adguard.ErrorKindStatus)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusServiceUnavailable, clientErr.StatusCode)
			assert.Equal(t, deprecatedProblemMediaType, clientErr.ContentType)
			assert.JSONEq(t, deprecatedStatusBody, string(clientErr.Body))
		})
	}
}

// TestDeprecatedCompatibilityResponseLimits verifies that every deprecated
// operation bounds its complete response body.
func TestDeprecatedCompatibilityResponseLimits(t *testing.T) {
	t.Parallel()

	const limit = int64(3)

	tests := deprecatedOperationCases()
	for index := range tests {
		test := &tests[index]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newDeprecatedResponseServer(
				t,
				http.StatusOK,
				deprecatedJSONMediaType,
				"overflow",
			)
			client := newDeprecatedTestClient(t, server, limit)

			_, err := test.call(t.Context(), client)

			clientErr := requireDeprecatedError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, limit, clientErr.Limit)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
		})
	}
}

// TestDeprecatedCompatibilityResponseErrors verifies legacy JSON shape and
// media-type requirements.
func TestDeprecatedCompatibilityResponseErrors(t *testing.T) {
	t.Parallel()

	for _, test := range deprecatedResponseErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newDeprecatedResponseServer(
				t,
				http.StatusOK,
				test.contentType,
				test.body,
			)
			client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

			_, err := test.call(t.Context(), client)

			clientErr := requireDeprecatedError(t, err, test.kind)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.wantContentType, clientErr.ContentType)
			require.Error(t, clientErr.Err)
		})
	}
}

// TestDeprecatedCompatibilityLegacyOptionalFields verifies that the legacy
// configuration schemas do not inherit canonical required-field validation.
func TestDeprecatedCompatibilityLegacyOptionalFields(t *testing.T) {
	t.Parallel()

	t.Run("query log config", func(t *testing.T) {
		t.Parallel()

		server := newDeprecatedResponseServer(t, http.StatusOK, deprecatedJSONMediaType, `{}`)
		client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

		config, err := client.QueryLogInfo(t.Context())

		require.NoError(t, err)
		require.NotNil(t, config)
		assert.Equal(t, adguard.QueryLogConfig{}, *config)
	})

	t.Run("stats config", func(t *testing.T) {
		t.Parallel()

		server := newDeprecatedResponseServer(t, http.StatusOK, deprecatedJSONMediaType, `{}`)
		client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

		config, err := client.StatsInfo(t.Context())

		require.NoError(t, err)
		require.NotNil(t, config)
		assert.Equal(t, adguard.StatsConfig{}, *config)
	})
}

// TestDeprecatedCompatibilityEmptyValues verifies explicit empty arrays and the
// documented default-language sentinel.
func TestDeprecatedCompatibilityEmptyValues(t *testing.T) {
	t.Parallel()

	t.Run("available services", func(t *testing.T) {
		t.Parallel()

		server := newDeprecatedResponseServer(t, http.StatusOK, deprecatedJSONMediaType, `[]`)
		client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

		services, err := client.BlockedServicesAvailableServices(t.Context())

		require.NoError(t, err)
		assert.NotNil(t, services)
		assert.Empty(t, services)
	})

	t.Run("configured services", func(t *testing.T) {
		t.Parallel()

		server := newDeprecatedResponseServer(t, http.StatusOK, deprecatedJSONMediaType, `[]`)
		client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

		services, err := client.BlockedServicesList(t.Context())

		require.NoError(t, err)
		assert.NotNil(t, services)
		assert.Empty(t, services)
	})

	t.Run("default language", func(t *testing.T) {
		t.Parallel()

		server := newDeprecatedResponseServer(
			t,
			http.StatusOK,
			deprecatedJSONMediaType,
			`{"language":""}`,
		)
		client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

		language, err := client.CurrentLanguage(t.Context())

		require.NoError(t, err)
		assert.Empty(t, language)
	})
}

// TestDeprecatedCompatibilityBlockedServicesSetBody verifies the optional-body
// distinction between nil and an explicitly empty service list.
func TestDeprecatedCompatibilityBlockedServicesSetBody(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		services    []string
		requestBody string
	}{
		{name: "omitted"},
		{name: "explicit empty", services: []string{}, requestBody: `[]`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan deprecatedRequestCapture, 1)
			server := newDeprecatedCapturingServer(
				t,
				http.StatusOK,
				"",
				"",
				captured,
			)
			client := newDeprecatedTestClient(t, server, deprecatedResponseLimit)

			err := client.BlockedServicesSet(t.Context(), test.services)

			require.NoError(t, err)

			request := <-captured

			assert.Equal(t, http.MethodPost, request.method)
			assert.Equal(t, "/control/blocked_services/set", request.path)

			if test.requestBody == "" {
				assert.Empty(t, request.body)
				assert.Zero(t, request.contentLength)
				assert.Empty(t, request.contentType)

				return
			}

			assert.JSONEq(t, test.requestBody, string(request.body))
			assert.Positive(t, request.contentLength)
			//nolint:testifylint // encoded-compare: Content-Type is a media type, not encoded JSON.
			assert.Equal(t, deprecatedJSONMediaType, request.contentType)
		})
	}
}

// deprecatedOperationCases returns every pinned compatibility request contract.
func deprecatedOperationCases() []deprecatedOperationCase {
	ignoredEnabled := true

	return []deprecatedOperationCase{
		{
			name:                "query log info",
			method:              http.MethodGet,
			operation:           "query_log_info",
			path:                "/control/querylog_info",
			responseBody:        `{"enabled":true,"interval":1,"anonymize_client_ip":true}`,
			responseContentType: deprecatedJSONMediaType,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.QueryLogInfo(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				config, ok := result.(*adguard.QueryLogConfig)
				require.True(t, ok)
				assert.Equal(
					t,
					adguard.QueryLogConfig{
						Enabled:           true,
						Interval:          1,
						AnonymizeClientIP: true,
					},
					*config,
				)
			},
		},
		{
			name:        "query log config",
			method:      http.MethodPost,
			operation:   "query_log_config",
			path:        "/control/querylog_config",
			requestBody: `{"enabled":false,"interval":0,"anonymize_client_ip":true}`,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				err := client.QueryLogConfig(ctx, adguard.QueryLogConfig{
					Enabled:           false,
					Interval:          0,
					AnonymizeClientIP: true,
					Ignored:           []string{"localhost"},
					IgnoredEnabled:    &ignoredEnabled,
				})

				return nil, err
			},
		},
		{
			name:                "stats info",
			method:              http.MethodGet,
			operation:           "stats_info",
			path:                "/control/stats_info",
			responseBody:        `{"interval":7}`,
			responseContentType: deprecatedJSONMediaType,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.StatsInfo(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				config, ok := result.(*adguard.StatsConfig)
				require.True(t, ok)
				assert.Equal(t, adguard.StatsConfig{Interval: 7}, *config)
			},
		},
		{
			name:        "stats config",
			method:      http.MethodPost,
			operation:   "stats_config",
			path:        "/control/stats_config",
			requestBody: `{"interval":90}`,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				err := client.StatsConfig(ctx, adguard.StatsConfig{
					Enabled:        true,
					Interval:       90,
					Ignored:        []string{"localhost"},
					IgnoredEnabled: &ignoredEnabled,
				})

				return nil, err
			},
		},
		{
			name:      "safesearch enable",
			method:    http.MethodPost,
			operation: "safesearch_enable",
			path:      "/control/safesearch/enable",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.SafesearchEnable(ctx)
			},
		},
		{
			name:      "safesearch disable",
			method:    http.MethodPost,
			operation: "safesearch_disable",
			path:      "/control/safesearch/disable",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.SafesearchDisable(ctx)
			},
		},
		{
			name:                "available blocked services",
			method:              http.MethodGet,
			operation:           "blocked_services_available_services",
			path:                "/control/blocked_services/services",
			responseBody:        `["youtube","reddit"]`,
			responseContentType: deprecatedJSONMediaType,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesAvailableServices(ctx)
			},
			verify: assertDeprecatedServices,
		},
		{
			name:                "configured blocked services",
			method:              http.MethodGet,
			operation:           "blocked_services_list",
			path:                "/control/blocked_services/list",
			responseBody:        `["youtube","reddit"]`,
			responseContentType: deprecatedJSONMediaType,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesList(ctx)
			},
			verify: assertDeprecatedServices,
		},
		{
			name:        "set blocked services",
			method:      http.MethodPost,
			operation:   "blocked_services_set",
			path:        "/control/blocked_services/set",
			requestBody: `["youtube","reddit"]`,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.BlockedServicesSet(ctx, []string{"youtube", "reddit"})
			},
		},
		{
			name:        "change language",
			method:      http.MethodPost,
			operation:   "change_language",
			path:        "/control/i18n/change_language",
			requestBody: `{"language":"de"}`,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.ChangeLanguage(ctx, "de")
			},
		},
		{
			name:                "current language",
			method:              http.MethodGet,
			operation:           "current_language",
			path:                "/control/i18n/current_language",
			responseBody:        `{"language":"de"}`,
			responseContentType: deprecatedJSONMediaType,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.CurrentLanguage(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				language, ok := result.(string)
				require.True(t, ok)
				assert.Equal(t, "de", language)
			},
		},
	}
}

// deprecatedResponseErrorCases returns legacy response and media-type failures.
func deprecatedResponseErrorCases() []deprecatedResponseErrorCase {
	return []deprecatedResponseErrorCase{
		{
			name:        "query log null object",
			operation:   "query_log_info",
			method:      http.MethodGet,
			body:        `null`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.QueryLogInfo(ctx)
			},
		},
		{
			name:        "stats malformed object",
			operation:   "stats_info",
			method:      http.MethodGet,
			body:        `{`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.StatsInfo(ctx)
			},
		},
		{
			name:        "available services null array",
			operation:   "blocked_services_available_services",
			method:      http.MethodGet,
			body:        `null`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesAvailableServices(ctx)
			},
		},
		{
			name:        "configured services null element",
			operation:   "blocked_services_list",
			method:      http.MethodGet,
			body:        `["youtube",null]`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesList(ctx)
			},
		},
		{
			name:        "current language null object",
			operation:   "current_language",
			method:      http.MethodGet,
			body:        `null`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.CurrentLanguage(ctx)
			},
		},
		{
			name:        "current language missing property",
			operation:   "current_language",
			method:      http.MethodGet,
			body:        `{}`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.CurrentLanguage(ctx)
			},
		},
		{
			name:        "current language null property",
			operation:   "current_language",
			method:      http.MethodGet,
			body:        `{"language":null}`,
			contentType: deprecatedJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.CurrentLanguage(ctx)
			},
		},
		{
			name:            "query log content type",
			operation:       "query_log_info",
			method:          http.MethodGet,
			body:            `{}`,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			wantContentType: "text/plain",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.QueryLogInfo(ctx)
			},
		},
		{
			name:            "stats content type",
			operation:       "stats_info",
			method:          http.MethodGet,
			body:            `{}`,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			wantContentType: "text/plain",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.StatsInfo(ctx)
			},
		},
		{
			name:            "available services content type",
			operation:       "blocked_services_available_services",
			method:          http.MethodGet,
			body:            `[]`,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			wantContentType: "text/plain",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesAvailableServices(ctx)
			},
		},
		{
			name:            "configured services content type",
			operation:       "blocked_services_list",
			method:          http.MethodGet,
			body:            `[]`,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			wantContentType: "text/plain",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesList(ctx)
			},
		},
		{
			name:            "current language content type",
			operation:       "current_language",
			method:          http.MethodGet,
			body:            `{"language":"de"}`,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			wantContentType: "text/plain",
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.CurrentLanguage(ctx)
			},
		},
	}
}

// assertDeprecatedServices verifies the shared blocked-service result.
func assertDeprecatedServices(t *testing.T, result any) {
	t.Helper()

	services, ok := result.([]string)
	require.True(t, ok)
	assert.Equal(t, []string{"youtube", "reddit"}, services)
}

// assertDeprecatedRequest verifies one exact deprecated HTTP request.
func assertDeprecatedRequest(
	t *testing.T,
	test deprecatedOperationCase,
	request deprecatedRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	assert.Equal(t, test.method, request.method)
	assert.Equal(t, test.path, request.path)
	assert.Empty(t, request.query)
	//nolint:testifylint // encoded-compare: Accept is a media type, not encoded JSON.
	assert.Equal(t, deprecatedJSONMediaType, request.accept)
	assert.Equal(t, deprecatedTestUserAgent, request.userAgent)
	assert.True(t, request.hasAuth)
	assert.Equal(t, deprecatedTestUsername, request.username)
	assert.Equal(t, deprecatedTestPassword, request.password)

	if test.requestBody == "" {
		assert.Empty(t, request.body)
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.contentType)

		return
	}

	assert.JSONEq(t, test.requestBody, string(request.body))
	assert.Positive(t, request.contentLength)
	//nolint:testifylint // encoded-compare: Content-Type is a media type, not encoded JSON.
	assert.Equal(t, deprecatedJSONMediaType, request.contentType)
}

// newDeprecatedTestClient creates a concrete client routed to an in-memory server.
func newDeprecatedTestClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		deprecatedTestBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(deprecatedTestUsername, deprecatedTestPassword),
		adguard.WithRequestTimeout(deprecatedRequestTimeout),
		adguard.WithMaxResponseBodySize(limit),
		adguard.WithUserAgent(deprecatedTestUserAgent),
	)
	require.NoError(t, err)

	return client
}

// newDeprecatedCapturingServer creates a server that records its request.
func newDeprecatedCapturingServer(
	t *testing.T,
	status int,
	contentType string,
	body string,
	captured chan<- deprecatedRequestCapture,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body)
		username, password, hasAuth := r.BasicAuth()

		captured <- deprecatedRequestCapture{
			accept:        r.Header.Get("Accept"),
			body:          requestBody,
			contentLength: r.ContentLength,
			contentType:   r.Header.Get("Content-Type"),
			hasAuth:       hasAuth,
			method:        r.Method,
			password:      password,
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			readErr:       err,
			userAgent:     r.Header.Get("User-Agent"),
			username:      username,
		}

		writeDeprecatedResponse(t, w, status, contentType, body)
	}))
}

// newDeprecatedResponseServer creates a server returning a fixed response.
func newDeprecatedResponseServer(
	t *testing.T,
	status int,
	contentType string,
	body string,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeDeprecatedResponse(t, w, status, contentType, body)
	}))
}

// writeDeprecatedResponse writes a fixed test response.
func writeDeprecatedResponse(
	t *testing.T,
	w http.ResponseWriter,
	status int,
	contentType string,
	body string,
) {
	t.Helper()

	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(status)

	if body == "" {
		return
	}

	_, err := io.WriteString(w, body)
	assert.NoError(t, err)
}

// requireDeprecatedError extracts one expected structured client error.
func requireDeprecatedError(
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
