// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
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

// filteringIntegrationRequestCase describes one filtering HTTP request contract.
type filteringIntegrationRequestCase struct {
	name         string
	method       string
	path         string
	rawQuery     string
	requestBody  string
	responseType string
	responseBody string
	call         func(context.Context, *adguard.Client) error
}

// filteringIntegrationStatusErrorCase describes one structured HTTP error contract.
type filteringIntegrationStatusErrorCase struct {
	name      string
	operation string
	method    string
	path      string
	call      func(context.Context, *adguard.Client) error
}

// filteringIntegrationResponseErrorCase describes one response-validation error.
type filteringIntegrationResponseErrorCase struct {
	name         string
	operation    string
	method       string
	contentType  string
	responseBody string
	wantKind     adguard.ErrorKind
	call         func(context.Context, *adguard.Client) error
}

const (
	// The concrete client test username.
	filteringIntegrationUsername = "filtering-user"
	// The concrete client test password.
	filteringIntegrationPassword = "filtering-password"
	// An explicitly present empty JSON object.
	filteringIntegrationEmptyObject = "{}"
	// The host used by request-contract tests.
	filteringIntegrationHostName = "example.org"
	// The successful JSON response media type.
	filteringIntegrationJSONMediaType = "application/json; charset=utf-8"
	// The deliberately invalid plain-text response media type.
	filteringIntegrationTextMediaType = "text/plain"
	// The status contract name shared by the filtering request cases.
	filteringIntegrationStatusName = "status"
	// The truncated status JSON returned by the malformed-response server.
	filteringIntegrationTruncatedJSON = `{"enabled":`
	// The configured test client User-Agent.
	filteringIntegrationUserAgent = "filtering-integration-client/1.0"
	// The check-host endpoint path.
	filteringIntegrationCheckHostPath = "/api/control/filtering/check_host"
	// The check-host operation name.
	filteringIntegrationCheckHostOperation = "filtering_check_host"
	// The refresh endpoint path.
	filteringIntegrationRefreshPath = "/api/control/filtering/refresh"
	// The set-rules endpoint path.
	filteringIntegrationSetRulesPath = "/api/control/filtering/set_rules"
	// The set-URL endpoint path.
	filteringIntegrationSetURLPath = "/api/control/filtering/set_url"
)

// TestFilteringIntegrationRequestContracts verifies every filtering endpoint's complete HTTP contract.
func TestFilteringIntegrationRequestContracts(t *testing.T) {
	t.Parallel()

	groups := [][]filteringIntegrationRequestCase{
		filteringIntegrationReadCases(),
		filteringIntegrationMutationCases(),
		filteringIntegrationOptionalBodyCases(),
	}
	for _, group := range groups {
		for _, test := range group {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				assertFilteringIntegrationRequest(t, test)
			})
		}
	}
}

// TestFilteringIntegrationPreservesExplicitValues verifies explicit false, zero, and empty response values.
func TestFilteringIntegrationPreservesExplicitValues(t *testing.T) {
	t.Parallel()

	t.Run("status", testFilteringIntegrationStatusValues)
	t.Run("refresh", testFilteringIntegrationRefreshValues)
	t.Run("check host", testFilteringIntegrationHostValues)
}

// TestFilteringIntegrationReturnsStructuredStatusErrors verifies operation and response metadata on HTTP failures.
func TestFilteringIntegrationReturnsStructuredStatusErrors(t *testing.T) {
	t.Parallel()

	for _, test := range filteringIntegrationStatusErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertFilteringIntegrationStatusError(t, test)
		})
	}
}

// TestFilteringIntegrationReturnsStructuredResponseErrors verifies JSON and media-type failures.
func TestFilteringIntegrationReturnsStructuredResponseErrors(t *testing.T) {
	t.Parallel()

	for _, test := range filteringIntegrationResponseErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertFilteringIntegrationResponseError(t, test)
		})
	}
}

// testFilteringIntegrationStatusValues verifies explicit filtering status values.
func testFilteringIntegrationStatusValues(t *testing.T) {
	t.Parallel()
	t.Helper()

	body := `{"enabled":false,"interval":0,"filters":[],` +
		`"whitelist_filters":[],"user_rules":[]}`
	server := newFilteringIntegrationJSONServer(t, body)
	client := newFilteringIntegrationClient(t, server)

	status, err := client.FilteringStatus(t.Context())

	require.NoError(t, err)
	require.NotNil(t, status.Enabled)
	assert.False(t, *status.Enabled)
	require.NotNil(t, status.Interval)
	assert.Zero(t, *status.Interval)
	require.NotNil(t, status.Filters)
	assert.Empty(t, *status.Filters)
	require.NotNil(t, status.WhitelistFilters)
	assert.Empty(t, *status.WhitelistFilters)
	require.NotNil(t, status.UserRules)
	assert.Empty(t, *status.UserRules)
}

// testFilteringIntegrationRefreshValues verifies an explicit zero refresh count.
func testFilteringIntegrationRefreshValues(t *testing.T) {
	t.Parallel()
	t.Helper()

	server := newFilteringIntegrationJSONServer(t, `{"updated":0}`)
	client := newFilteringIntegrationClient(t, server)

	result, err := client.RefreshFiltering(t.Context(), nil)

	require.NoError(t, err)
	require.NotNil(t, result.Updated)
	assert.Zero(t, *result.Updated)
}

// testFilteringIntegrationHostValues verifies explicit host-check values.
func testFilteringIntegrationHostValues(t *testing.T) {
	t.Parallel()
	t.Helper()

	body := `{"reason":"FilteredBlackList","filter_id":0,"rule":"",` +
		`"rules":[],"service_name":"","cname":"","ip_addrs":[]}`
	server := newFilteringIntegrationJSONServer(t, body)
	client := newFilteringIntegrationClient(t, server)

	result, err := client.CheckFilteredHost(t.Context(), adguard.CheckHostRequest{
		Name:   filteringIntegrationHostName,
		Client: nil,
		QType:  nil,
	})

	require.NoError(t, err)
	require.NotNil(t, result.Reason)
	assert.Equal(t, adguard.FilteringReasonFilteredBlackList, *result.Reason)
	require.NotNil(t, result.FilterID)
	assert.Zero(t, *result.FilterID)
	require.NotNil(t, result.Rule)
	assert.Empty(t, *result.Rule)
	require.NotNil(t, result.Rules)
	assert.Empty(t, *result.Rules)
	require.NotNil(t, result.ServiceName)
	assert.Empty(t, *result.ServiceName)
	require.NotNil(t, result.CNAME)
	assert.Empty(t, *result.CNAME)
	require.NotNil(t, result.IPAddresses)
	assert.Empty(t, *result.IPAddresses)
}

// filteringIntegrationReadCases returns the filtering read request contracts.
//
// Returns:
//   - The status and host-check request contracts.
func filteringIntegrationReadCases() []filteringIntegrationRequestCase {
	empty := ""

	return []filteringIntegrationRequestCase{
		{
			name:         filteringIntegrationStatusName,
			method:       http.MethodGet,
			path:         "/api/control/filtering/status",
			rawQuery:     "",
			requestBody:  "",
			responseType: filteringIntegrationJSONMediaType,
			responseBody: filteringIntegrationEmptyObject,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.FilteringStatus(ctx)

				return err
			},
		},
		{
			name:         "check host includes empty optional query values",
			method:       http.MethodGet,
			path:         filteringIntegrationCheckHostPath,
			rawQuery:     "client=&name=example.org&qtype=",
			requestBody:  "",
			responseType: filteringIntegrationJSONMediaType,
			responseBody: filteringIntegrationEmptyObject,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.CheckFilteredHost(ctx, adguard.CheckHostRequest{
					Name:   filteringIntegrationHostName,
					Client: &empty,
					QType:  &empty,
				})

				return err
			},
		},
		{
			name:         "check host omits absent optional query values",
			method:       http.MethodGet,
			path:         filteringIntegrationCheckHostPath,
			rawQuery:     "name=example.org",
			requestBody:  "",
			responseType: filteringIntegrationJSONMediaType,
			responseBody: filteringIntegrationEmptyObject,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.CheckFilteredHost(ctx, adguard.CheckHostRequest{
					Name:   filteringIntegrationHostName,
					Client: nil,
					QType:  nil,
				})

				return err
			},
		},
	}
}

// filteringIntegrationMutationCases returns filtering mutation request contracts.
//
// Returns:
//   - The configuration, URL, and rules request contracts.
func filteringIntegrationMutationCases() []filteringIntegrationRequestCase {
	return slices.Concat(
		filteringIntegrationConfigCases(),
		filteringIntegrationURLCases(),
		filteringIntegrationRulesCases(),
	)
}

// filteringIntegrationConfigCases returns the configuration request contract.
//
// Returns:
//   - The configuration request contract.
func filteringIntegrationConfigCases() []filteringIntegrationRequestCase {
	disabled := false
	zero := int64(0)

	return []filteringIntegrationRequestCase{
		{
			name:         "update config preserves false and zero",
			method:       http.MethodPost,
			path:         "/api/control/filtering/config",
			rawQuery:     "",
			requestBody:  `{"enabled":false,"interval":0}`,
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateFilteringConfig(ctx, adguard.FilteringConfig{
					Enabled:  &disabled,
					Interval: &zero,
				})
			},
		},
	}
}

// filteringIntegrationURLCases returns the URL request contracts.
//
// Returns:
//   - The add, remove, and set URL request contracts.
func filteringIntegrationURLCases() []filteringIntegrationRequestCase {
	disabled := false
	empty := ""

	return []filteringIntegrationRequestCase{
		{
			name:         "add URL preserves empty strings and false",
			method:       http.MethodPost,
			path:         "/api/control/filtering/add_url",
			rawQuery:     "",
			requestBody:  `{"name":"","url":"","whitelist":false}`,
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.AddFilteringURL(ctx, adguard.AddFilteringURLRequest{
					Name:      &empty,
					URL:       &empty,
					Whitelist: &disabled,
				})
			},
		},
		{
			name:         "remove URL preserves empty string and false",
			method:       http.MethodPost,
			path:         "/api/control/filtering/remove_url",
			rawQuery:     "",
			requestBody:  `{"url":"","whitelist":false}`,
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.RemoveFilteringURL(ctx, adguard.RemoveFilteringURLRequest{
					URL:       &empty,
					Whitelist: &disabled,
				})
			},
		},
		{
			name:     "set URL preserves nested and outer empty values",
			method:   http.MethodPost,
			path:     filteringIntegrationSetURLPath,
			rawQuery: "",
			requestBody: `{"data":{"enabled":false,"name":"","url":""},` +
				`"url":"","whitelist":false}`,
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringURL(ctx, &adguard.SetFilteringURLRequest{
					Data: &adguard.FilteringURLData{
						Enabled: false,
						Name:    "",
						URL:     "",
					},
					URL:       &empty,
					Whitelist: &disabled,
				})
			},
		},
	}
}

// filteringIntegrationRulesCases returns the rules request contract.
//
// Returns:
//   - The rules request contract.
func filteringIntegrationRulesCases() []filteringIntegrationRequestCase {
	emptyRules := []string{}

	return []filteringIntegrationRequestCase{
		{
			name:         "set rules preserves an empty list",
			method:       http.MethodPost,
			path:         filteringIntegrationSetRulesPath,
			rawQuery:     "",
			requestBody:  `{"rules":[]}`,
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringRules(ctx, &adguard.SetFilteringRulesRequest{
					Rules: &emptyRules,
				})
			},
		},
	}
}

// filteringIntegrationOptionalBodyCases returns request-body presence contracts.
//
// Returns:
//   - The omitted, empty-object, and explicit-value request contracts.
func filteringIntegrationOptionalBodyCases() []filteringIntegrationRequestCase {
	return slices.Concat(
		filteringIntegrationSetURLBodyCases(),
		filteringIntegrationRefreshBodyCases(),
		filteringIntegrationRulesBodyCases(),
	)
}

// filteringIntegrationSetURLBodyCases returns the set-URL body-presence contract.
//
// Returns:
//   - The omitted set-URL body request contract.
func filteringIntegrationSetURLBodyCases() []filteringIntegrationRequestCase {
	return []filteringIntegrationRequestCase{
		{
			name:         "set URL omits the body for a nil request",
			method:       http.MethodPost,
			path:         filteringIntegrationSetURLPath,
			rawQuery:     "",
			requestBody:  "",
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringURL(ctx, nil)
			},
		},
	}
}

// filteringIntegrationRefreshBodyCases returns refresh body-presence contracts.
//
// Returns:
//   - The explicit-false, empty-object, and omitted refresh request contracts.
func filteringIntegrationRefreshBodyCases() []filteringIntegrationRequestCase {
	disabled := false

	return []filteringIntegrationRequestCase{
		{
			name:         "refresh preserves explicit false",
			method:       http.MethodPost,
			path:         filteringIntegrationRefreshPath,
			rawQuery:     "",
			requestBody:  `{"whitelist":false}`,
			responseType: filteringIntegrationJSONMediaType,
			responseBody: `{"updated":2}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.RefreshFiltering(ctx, &adguard.RefreshFilteringRequest{
					Whitelist: &disabled,
				})

				return err
			},
		},
		{
			name:         "refresh sends an empty object for nil fields",
			method:       http.MethodPost,
			path:         filteringIntegrationRefreshPath,
			rawQuery:     "",
			requestBody:  filteringIntegrationEmptyObject,
			responseType: filteringIntegrationJSONMediaType,
			responseBody: `{"updated":0}`,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.RefreshFiltering(ctx, &adguard.RefreshFilteringRequest{
					Whitelist: nil,
				})

				return err
			},
		},
		{
			name:         "refresh omits the body for a nil request",
			method:       http.MethodPost,
			path:         filteringIntegrationRefreshPath,
			rawQuery:     "",
			requestBody:  "",
			responseType: filteringIntegrationJSONMediaType,
			responseBody: filteringIntegrationEmptyObject,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.RefreshFiltering(ctx, nil)

				return err
			},
		},
	}
}

// filteringIntegrationRulesBodyCases returns set-rules body-presence contracts.
//
// Returns:
//   - The empty-object and omitted set-rules request contracts.
func filteringIntegrationRulesBodyCases() []filteringIntegrationRequestCase {
	return []filteringIntegrationRequestCase{
		{
			name:         "set rules sends an empty object for nil rules",
			method:       http.MethodPost,
			path:         filteringIntegrationSetRulesPath,
			rawQuery:     "",
			requestBody:  filteringIntegrationEmptyObject,
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringRules(ctx, &adguard.SetFilteringRulesRequest{
					Rules: nil,
				})
			},
		},
		{
			name:         "set rules omits the body for a nil request",
			method:       http.MethodPost,
			path:         filteringIntegrationSetRulesPath,
			rawQuery:     "",
			requestBody:  "",
			responseType: "",
			responseBody: "",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringRules(ctx, nil)
			},
		},
	}
}

// filteringIntegrationStatusErrorCases returns structured HTTP error contracts.
//
// Returns:
//   - The status error case for every filtering operation.
func filteringIntegrationStatusErrorCases() []filteringIntegrationStatusErrorCase {
	return slices.Concat(
		filteringIntegrationReadStatusErrorCases(),
		filteringIntegrationConfigStatusErrorCases(),
		filteringIntegrationMutationStatusErrorCases(),
	)
}

// filteringIntegrationReadStatusErrorCases returns read-operation HTTP error contracts.
//
// Returns:
//   - The status and check-host error contracts.
func filteringIntegrationReadStatusErrorCases() []filteringIntegrationStatusErrorCase {
	return []filteringIntegrationStatusErrorCase{
		{
			name:      filteringIntegrationStatusName,
			operation: "filtering_status",
			method:    http.MethodGet,
			path:      "/api/control/filtering/status",
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.FilteringStatus(ctx)

				return err
			},
		},
		{
			name:      "check host",
			operation: filteringIntegrationCheckHostOperation,
			method:    http.MethodGet,
			path:      filteringIntegrationCheckHostPath,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.CheckFilteredHost(ctx, adguard.CheckHostRequest{
					Name:   filteringIntegrationHostName,
					Client: nil,
					QType:  nil,
				})

				return err
			},
		},
	}
}

// filteringIntegrationConfigStatusErrorCases returns configuration HTTP error contracts.
//
// Returns:
//   - The config, add-URL, and remove-URL error contracts.
func filteringIntegrationConfigStatusErrorCases() []filteringIntegrationStatusErrorCase {
	return []filteringIntegrationStatusErrorCase{
		{
			name:      "update config",
			operation: "filtering_config",
			method:    http.MethodPost,
			path:      "/api/control/filtering/config",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateFilteringConfig(ctx, adguard.FilteringConfig{
					Enabled:  nil,
					Interval: nil,
				})
			},
		},
		{
			name:      "add URL",
			operation: "filtering_add_url",
			method:    http.MethodPost,
			path:      "/api/control/filtering/add_url",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.AddFilteringURL(ctx, adguard.AddFilteringURLRequest{
					Name:      nil,
					URL:       nil,
					Whitelist: nil,
				})
			},
		},
		{
			name:      "remove URL",
			operation: "filtering_remove_url",
			method:    http.MethodPost,
			path:      "/api/control/filtering/remove_url",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.RemoveFilteringURL(ctx, adguard.RemoveFilteringURLRequest{
					URL:       nil,
					Whitelist: nil,
				})
			},
		},
	}
}

// filteringIntegrationMutationStatusErrorCases returns mutation HTTP error contracts.
//
// Returns:
//   - The set-URL, refresh, and set-rules error contracts.
func filteringIntegrationMutationStatusErrorCases() []filteringIntegrationStatusErrorCase {
	return []filteringIntegrationStatusErrorCase{
		{
			name:      "set URL",
			operation: "filtering_set_url",
			method:    http.MethodPost,
			path:      filteringIntegrationSetURLPath,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringURL(ctx, nil)
			},
		},
		{
			name:      "refresh",
			operation: "filtering_refresh",
			method:    http.MethodPost,
			path:      filteringIntegrationRefreshPath,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.RefreshFiltering(ctx, nil)

				return err
			},
		},
		{
			name:      "set rules",
			operation: "filtering_set_rules",
			method:    http.MethodPost,
			path:      filteringIntegrationSetRulesPath,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.SetFilteringRules(ctx, nil)
			},
		},
	}
}

// filteringIntegrationResponseErrorCases returns response-validation error contracts.
//
// Returns:
//   - The malformed JSON, empty JSON, invalid reason, and media-type cases.
func filteringIntegrationResponseErrorCases() []filteringIntegrationResponseErrorCase {
	return []filteringIntegrationResponseErrorCase{
		{
			name:         "malformed status JSON",
			operation:    "filtering_status",
			method:       http.MethodGet,
			contentType:  filteringIntegrationJSONMediaType,
			responseBody: filteringIntegrationTruncatedJSON,
			wantKind:     adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.FilteringStatus(ctx)

				return err
			},
		},
		{
			name:         "empty refresh JSON",
			operation:    "filtering_refresh",
			method:       http.MethodPost,
			contentType:  filteringIntegrationJSONMediaType,
			responseBody: "",
			wantKind:     adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.RefreshFiltering(ctx, nil)

				return err
			},
		},
		{
			name:         "invalid host reason",
			operation:    filteringIntegrationCheckHostOperation,
			method:       http.MethodGet,
			contentType:  filteringIntegrationJSONMediaType,
			responseBody: `{"reason":"Unknown"}`,
			wantKind:     adguard.ErrorKindJSON,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.CheckFilteredHost(ctx, adguard.CheckHostRequest{
					Name:   filteringIntegrationHostName,
					Client: nil,
					QType:  nil,
				})

				return err
			},
		},
		{
			name:         "invalid host response media type",
			operation:    filteringIntegrationCheckHostOperation,
			method:       http.MethodGet,
			contentType:  filteringIntegrationTextMediaType,
			responseBody: filteringIntegrationEmptyObject,
			wantKind:     adguard.ErrorKindContentType,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.CheckFilteredHost(ctx, adguard.CheckHostRequest{
					Name:   filteringIntegrationHostName,
					Client: nil,
					QType:  nil,
				})

				return err
			},
		},
	}
}

// assertFilteringIntegrationMetadata verifies one request's method, path, query, and headers.
//
// Parameters:
//   - r: The received HTTP request.
//   - test: The request contract to exercise.
func assertFilteringIntegrationMetadata(
	t *testing.T,
	r *http.Request,
	test filteringIntegrationRequestCase,
) {
	t.Helper()

	// The media type every filtering request must advertise and send.
	expectedMediaType := blockedServicesIntegrationJSONContentType

	username, password, authenticated := r.BasicAuth()
	assert.True(t, authenticated)
	assert.Equal(t, filteringIntegrationUsername, username)
	assert.Equal(t, filteringIntegrationPassword, password)
	assert.Equal(t, test.method, r.Method)
	assert.Equal(t, test.path, r.URL.Path)
	assert.Equal(t, test.rawQuery, r.URL.RawQuery)
	assert.Equal(t, []string{expectedMediaType}, r.Header.Values("Accept"))
	assert.Equal(t, filteringIntegrationUserAgent, r.Header.Get("User-Agent"))

	if test.method == http.MethodGet {
		assert.Empty(t, r.Header.Get("Content-Type"))
	} else {
		assert.Equal(t, expectedMediaType, r.Header.Get("Content-Type"))
	}
}

// readFilteringIntegrationBody reads and closes one request body.
//
// Parameters:
//   - r: The received HTTP request.
//
// Returns:
//   - body: The bytes read from the request body.
//   - ok: Whether reading and closing the body succeeded.
func readFilteringIntegrationBody(t *testing.T, r *http.Request) ([]byte, bool) {
	t.Helper()

	body, err := io.ReadAll(r.Body)
	closeErr := r.Body.Close()

	assert.NoError(t, err)
	assert.NoError(t, closeErr)

	if err != nil || closeErr != nil {
		return nil, false
	}

	return body, true
}

// assertFilteringIntegrationBody verifies one request body's presence and JSON value.
//
// Parameters:
//   - body: The received request body.
//   - expected: The expected JSON body, or an empty string for no body.
func assertFilteringIntegrationBody(t *testing.T, body []byte, expected string) {
	t.Helper()

	if expected == "" {
		assert.Empty(t, body)

		return
	}

	assert.JSONEq(t, expected, string(body))
}

// writeFilteringIntegrationResponse writes one response with optional media type.
//
// Parameters:
//   - w: The response writer receiving the response.
//   - contentType: The response media type, or an empty string to omit it.
//   - body: The response body to write.
func writeFilteringIntegrationResponse(w http.ResponseWriter, contentType, body string) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	writeFilteringIntegrationBody(w, body)
}

// assertFilteringIntegrationRequest verifies one request and its successful response policy.
//
// Parameters:
//   - test: The request contract to exercise.
func assertFilteringIntegrationRequest(t *testing.T, test filteringIntegrationRequestCase) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assertFilteringIntegrationMetadata(t, r, test)

		body, ok := readFilteringIntegrationBody(t, r)
		if !ok {
			return
		}

		assertFilteringIntegrationBody(t, body, test.requestBody)

		writeFilteringIntegrationResponse(w, test.responseType, test.responseBody)
	}))
	client := newFilteringIntegrationClient(t, server)

	err := test.call(t.Context(), client)

	require.NoError(t, err)
}

// assertFilteringIntegrationStatusError verifies one structured HTTP error.
//
// Parameters:
//   - test: The HTTP error contract to exercise.
func assertFilteringIntegrationStatusError(t *testing.T, test filteringIntegrationStatusErrorCase) {
	t.Helper()

	const errorBody = `{"message":"invalid filtering request"}`

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, test.method, r.Method)
		assert.Equal(t, test.path, r.URL.Path)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		writeFilteringIntegrationBody(w, errorBody)
	}))
	client := newFilteringIntegrationClient(t, server)

	err := test.call(t.Context(), client)

	clientErr := requireFilteringIntegrationClientError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, test.operation, clientErr.Operation)
	assert.Equal(t, test.method, clientErr.Method)
	assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
	assert.Equal(t, "422 Unprocessable Entity", clientErr.Status)
	assert.Equal(t, "application/problem+json", clientErr.ContentType)
	assert.JSONEq(t, errorBody, string(clientErr.Body))
	assert.NoError(t, clientErr.Err)
}

// assertFilteringIntegrationResponseError verifies one structured response error.
//
// Parameters:
//   - test: The response error contract to exercise.
func assertFilteringIntegrationResponseError(
	t *testing.T,
	test filteringIntegrationResponseErrorCase,
) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", test.contentType)
		writeFilteringIntegrationBody(w, test.responseBody)
	}))
	client := newFilteringIntegrationClient(t, server)

	err := test.call(t.Context(), client)

	clientErr := requireFilteringIntegrationClientError(t, err, test.wantKind)
	assert.Equal(t, test.operation, clientErr.Operation)
	assert.Equal(t, test.method, clientErr.Method)
	assert.Error(t, clientErr.Err)
}

// writeFilteringIntegrationBody writes a response body while tolerating client disconnects.
//
// Parameters:
//   - w: The response writer receiving the body.
//   - body: The response body to write.
func writeFilteringIntegrationBody(w http.ResponseWriter, body string) {
	_, err := io.WriteString(w, body)
	if err != nil {
		return
	}
}

// requireFilteringIntegrationClientError extracts and verifies a structured client error.
//
// Parameters:
//   - err: The error to inspect.
//   - kind: The expected client error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireFilteringIntegrationClientError(
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

// Parameters:
//   - body: The JSON response body.
//
// Returns:
//   - server: The HTTP test server.
func newFilteringIntegrationJSONServer(t *testing.T, body string) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", filteringIntegrationJSONMediaType)
		writeFilteringIntegrationBody(w, body)
	}))
}

// newFilteringIntegrationClient creates a concrete client bound to a test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//
// Returns:
//   - client: The configured AdGuard client.
func newFilteringIntegrationClient(t *testing.T, server *httptest.Server) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		blockedServicesIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(filteringIntegrationUsername, filteringIntegrationPassword),
		adguard.WithUserAgent(filteringIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(4096),
	)
	require.NoError(t, err)

	return client
}
