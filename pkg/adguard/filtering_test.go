// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturedFilteringRequest contains request metadata captured by the filtering
// test server.
type capturedFilteringRequest struct {
	// body is the received request body.
	body []byte
	// contentType is the request Content-Type header.
	contentType string
	// method is the received HTTP method.
	method string
	// path is the received API path.
	path string
	// query is the received decoded query string.
	query url.Values
	// username is the received Basic Auth username.
	username string
	// password is the received Basic Auth password.
	password string
	// hasAuth reports whether Basic Auth was present.
	hasAuth bool
}

// filteringRequestContract describes one filtering request contract case.
type filteringRequestContract struct {
	// name is the subtest name.
	name string
	// method is the expected HTTP method.
	method string
	// path is the expected API path.
	path string
	// query is the expected decoded query string, or nil for no query.
	query url.Values
	// wantBody is the expected JSON request body, or an empty string for no body.
	wantBody string
	// responseBody is the response body returned by the test server.
	responseBody string
	// call invokes the filtering operation under test.
	call func(context.Context, *Client) error
}

const (
	// FilteringSetURLPath is the set-subscription request path.
	filteringSetURLPath = "/api/control/filtering/set_url"
	// FilteringRefreshPath is the refresh request path.
	filteringRefreshPath = "/api/control/filtering/refresh"
	// FilteringSetRulesPath is the set-rules request path.
	filteringSetRulesPath = "/api/control/filtering/set_rules"
	// FilteringAddURLPath is the add-subscription request path.
	filteringAddURLPath = "/api/control/filtering/add_url"
	// FilteringRemoveURLPath is the remove-subscription request path.
	filteringRemoveURLPath = "/api/control/filtering/remove_url"
	// FilteringHostName is the host used by filtering tests.
	filteringHostName = "example.org"
	// FilteringUpdatedZero is a successful response reporting zero updates.
	filteringUpdatedZero = `{"updated":0}`
	// FilteringEmptyObject is an explicitly present empty JSON request object.
	filteringEmptyObject = "{}"
	// FilteringTextPlainMediaType is a deliberately invalid JSON media type.
	filteringTextPlainMediaType = "text/plain"
	// FilteringTruncatedJSON is a deliberately malformed JSON response body.
	filteringTruncatedJSON = `{"enabled":`
	// FilteringNameQueryKey is the check-host query key carrying the host name.
	filteringNameQueryKey = "name"
	// FilteringTestFilterName is the filter name shared by the request contracts.
	filteringTestFilterName = "Example filter"
	// FilteringTestFilterURL is the filter URL shared by the request contracts.
	filteringTestFilterURL = "https://example.test/filter.txt"
	// FilteringTestOldURL is the replaced filter URL shared by the set-URL contracts.
	filteringTestOldURL = "https://example.test/old.txt"
)

// validFilteringStatusJSON is the complete filtering status response fixture.
const validFilteringStatusJSON = `{
	"enabled": true,
	"interval": 24,
	"filters": [{
		"enabled": true,
		"id": 1234,
		"last_updated": "2018-10-30T12:18:57+03:00",
		"name": "AdGuard Simplified Domain Names filter",
		"rules_count": 5912,
		"url": "https://example.test/filter.txt"
	}],
	"whitelist_filters": [],
	"user_rules": ["||example.org^"]
}`

// validFilteredHostJSON is the complete filtering host-check response fixture.
const validFilteredHostJSON = `{
	"reason": "FilteredBlackList",
	"filter_id": 1234,
	"rule": "||example.org^",
	"rules": [{"filter_list_id": 1234, "text": "||example.org^"}],
	"service_name": "example",
	"cname": "example.test",
	"ip_addrs": ["192.0.2.1"]
}`

// filteringSetURLBody is the expected set-subscription JSON request body.
var filteringSetURLBody = `{"data":{"enabled":false,"name":"Example filter",` +
	`"url":"https://example.test/filter.txt"},"url":"https://example.test/old.txt",` +
	`"whitelist":true}`

// TestClientFilteringRequestContract verifies every filtering operation's HTTP contract.
func TestClientFilteringRequestContract(t *testing.T) {
	t.Parallel()

	groups := [][]filteringRequestContract{
		filteringReadRequestContracts(),
		filteringConfigRequestContracts(),
		filteringAddURLRequestContracts(),
		filteringRemoveURLRequestContracts(),
		filteringSetURLRequestContracts(),
		filteringSetURLOmissionRequestContracts(),
		filteringRefreshRequestContracts(),
		filteringSetRulesRequestContracts(),
	}
	for _, group := range groups {
		testFilteringRequestContracts(t, group)
	}
}

// TestClientSetFilteringURLRejectsExplicitBodyWithoutData verifies local required-field validation.
func TestClientSetFilteringURLRejectsExplicitBodyWithoutData(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newFilteringTestClient(t, server, 4096)

	err := client.SetFilteringURL(t.Context(), &SetFilteringURLRequest{
		Data:      nil,
		URL:       nil,
		Whitelist: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, "filtering_set_url", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.Zero(t, requests.Load())
}

// TestClientFilteringStatusPresence verifies optional boolean decoding semantics.
func TestClientFilteringStatusPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		body     string
		want     *bool
		wantText string
	}{
		{name: safetyAbsentName, body: `{}`, want: nil, wantText: ""},
		{name: testNullJSON, body: `{"enabled":null}`, want: nil, wantText: ""},
		{name: safetyFalseName, body: `{"enabled":false}`, want: new(false), wantText: safetyFalseName},
		{name: safetyTrueName, body: `{"enabled":true}`, want: new(true), wantText: safetyTrueName},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := filteringJSONServer(t, test.body)
			client := newFilteringTestClient(t, server, int64(len(test.body)))

			status, err := client.FilteringStatus(t.Context())

			require.NoError(t, err)

			if test.want == nil {
				assert.Nil(t, status.Enabled)
			} else {
				require.NotNil(t, status.Enabled)
				assert.Equal(t, *test.want, *status.Enabled, test.wantText)
			}
		})
	}
}

// TestClientFilteringResponseModels verifies typed filtering responses.
func TestClientFilteringResponseModels(t *testing.T) {
	t.Parallel()

	t.Run("filtering status", testClientFilteringStatusResponse)
	t.Run("refresh", testClientFilteringRefreshResponse)
	t.Run("check host", testClientFilteringCheckHostResponse)
}

// testClientFilteringStatusResponse verifies status response decoding.
func testClientFilteringStatusResponse(t *testing.T) {
	t.Parallel()

	server := filteringJSONServer(t, validFilteringStatusJSON)
	client := newFilteringTestClient(t, server, int64(len(validFilteringStatusJSON)))

	status, err := client.FilteringStatus(t.Context())

	require.NoError(t, err)
	require.NotNil(t, status.Enabled)
	assert.True(t, *status.Enabled)
	require.NotNil(t, status.Interval)
	assert.Equal(t, int64(24), *status.Interval)
	require.NotNil(t, status.Filters)
	require.Len(t, *status.Filters, 1)

	filter := (*status.Filters)[0]
	assert.True(t, filter.Enabled)
	assert.Equal(t, int64(1234), filter.ID)
	assert.Equal(t, "AdGuard Simplified Domain Names filter", filter.Name)
	assert.Equal(t, uint32(5912), filter.RulesCount)
	assert.Equal(t, "https://example.test/filter.txt", filter.URL)
	require.NotNil(t, filter.LastUpdated)
	assert.Equal(t, "2018-10-30T12:18:57+03:00", filter.LastUpdated.Format(time.RFC3339))
	require.NotNil(t, status.WhitelistFilters)
	assert.Empty(t, *status.WhitelistFilters)
	require.NotNil(t, status.UserRules)
	assert.Equal(t, []string{"||example.org^"}, *status.UserRules)
}

// testClientFilteringRefreshResponse verifies refresh response decoding.
func testClientFilteringRefreshResponse(t *testing.T) {
	t.Parallel()

	server := filteringJSONServer(t, filteringUpdatedZero)
	client := newFilteringTestClient(t, server, int64(len(filteringUpdatedZero)))

	result, err := client.RefreshFiltering(t.Context(), &RefreshFilteringRequest{Whitelist: nil})

	require.NoError(t, err)
	require.NotNil(t, result.Updated)
	assert.Zero(t, *result.Updated)
}

// testClientFilteringCheckHostResponse verifies host-check response decoding.
func testClientFilteringCheckHostResponse(t *testing.T) {
	t.Parallel()

	server := filteringJSONServer(t, validFilteredHostJSON)
	client := newFilteringTestClient(t, server, int64(len(validFilteredHostJSON)))

	result, err := client.CheckFilteredHost(t.Context(), CheckHostRequest{
		Name:   filteringHostName,
		Client: nil,
		QType:  nil,
	})

	require.NoError(t, err)
	require.NotNil(t, result.Reason)
	assert.Equal(t, FilteringReasonFilteredBlackList, *result.Reason)
	require.NotNil(t, result.FilterID)
	assert.Equal(t, int64(1234), *result.FilterID)
	require.NotNil(t, result.Rule)
	assert.Equal(t, "||example.org^", *result.Rule)
	require.NotNil(t, result.Rules)
	require.Len(t, *result.Rules, 1)
	require.NotNil(t, (*result.Rules)[0].FilterListID)
	assert.Equal(t, int64(1234), *(*result.Rules)[0].FilterListID)
	require.NotNil(t, result.ServiceName)
	assert.Equal(t, "example", *result.ServiceName)
	require.NotNil(t, result.CNAME)
	assert.Equal(t, "example.test", *result.CNAME)
	require.NotNil(t, result.IPAddresses)
	assert.Equal(t, []string{clientsTestClientID}, *result.IPAddresses)
}

// TestClientFilteringRejectsInvalidSuccessResponses verifies JSON and media type policy.
func TestClientFilteringRejectsInvalidSuccessResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		contentType string
		body        string
		wantKind    ErrorKind
		operation   string
		method      string
		call        func(context.Context, *Client) error
	}{
		{
			name:        "malformed status JSON",
			contentType: testResponseMediaType,
			body:        filteringTruncatedJSON,
			wantKind:    ErrorKindJSON,
			operation:   "filtering_status",
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.FilteringStatus(ctx)

				return err
			},
		},
		{
			name:        "empty refresh JSON",
			contentType: testResponseMediaType,
			body:        "",
			wantKind:    ErrorKindJSON,
			operation:   "filtering_refresh",
			method:      http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RefreshFiltering(ctx, &RefreshFilteringRequest{Whitelist: nil})

				return err
			},
		},
		{
			name:        "wrong status content type",
			contentType: filteringTextPlainMediaType,
			body:        validFilteringStatusJSON,
			wantKind:    ErrorKindContentType,
			operation:   "filtering_status",
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.FilteringStatus(ctx)

				return err
			},
		},
		{
			name:        "wrong check host content type",
			contentType: "text/plain; charset=utf-8",
			body:        validFilteredHostJSON,
			wantKind:    ErrorKindContentType,
			operation:   "filtering_check_host",
			method:      http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.CheckFilteredHost(ctx, CheckHostRequest{
					Name:   filteringHostName,
					Client: nil,
					QType:  nil,
				})

				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				writeBody(w, test.body)
			}))
			client := newFilteringTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, test.wantKind)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
		})
	}
}

// TestClientFilteringRejectsNonSuccessResponses verifies status and method metadata.
func TestClientFilteringRejectsNonSuccessResponses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		call   func(context.Context, *Client) error
	}{
		{name: "status", method: http.MethodGet, call: func(ctx context.Context, client *Client) error {
			_, err := client.FilteringStatus(ctx)

			return err
		}},
		{name: "config", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			return client.UpdateFilteringConfig(ctx, FilteringConfig{Enabled: nil, Interval: nil})
		}},
		{name: "add URL", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			return client.AddFilteringURL(ctx, AddFilteringURLRequest{Name: nil, URL: nil, Whitelist: nil})
		}},
		{name: "remove URL", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			return client.RemoveFilteringURL(ctx, RemoveFilteringURLRequest{URL: nil, Whitelist: nil})
		}},
		{name: "set URL", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			return client.SetFilteringURL(ctx, nil)
		}},
		{name: "refresh", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			_, err := client.RefreshFiltering(ctx, nil)

			return err
		}},
		{name: "set rules", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			return client.SetFilteringRules(ctx, nil)
		}},
		{name: "check host", method: http.MethodGet, call: func(ctx context.Context, client *Client) error {
			_, err := client.CheckFilteredHost(ctx, CheckHostRequest{
				Name:   filteringHostName,
				Client: nil,
				QType:  nil,
			})

			return err
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", filteringTextPlainMediaType)
				w.WriteHeader(http.StatusTeapot)
				writeBody(w, "not available")
			}))
			client := newFilteringTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireClientError(t, err, ErrorKindStatus)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusTeapot, clientErr.StatusCode)
			assert.Equal(t, "not available", string(clientErr.Body))
		})
	}
}

// TestClientFilteringEnforcesResponseLimit verifies limits for JSON and empty-response operations.
func TestClientFilteringEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	t.Run("JSON", func(t *testing.T) {
		t.Parallel()

		server := filteringJSONServer(t, validFilteringStatusJSON)
		client := newFilteringTestClient(t, server, int64(len(validFilteringStatusJSON))-1)

		_, err := client.FilteringStatus(t.Context())

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, http.MethodGet, clientErr.Method)
		assert.Equal(t, int64(len(validFilteringStatusJSON))-1, clientErr.Limit)
	})

	t.Run("empty response", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", filteringTextPlainMediaType)
			writeBody(w, "unexpected")
		}))
		client := newFilteringTestClient(t, server, 4)

		err := client.UpdateFilteringConfig(t.Context(), FilteringConfig{Enabled: nil, Interval: nil})

		clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
		assert.Equal(t, http.MethodPost, clientErr.Method)
		assert.Equal(t, int64(4), clientErr.Limit)
	})
}

// TestClientFilteringHonorsCancellation verifies cancellation for GET and POST operations.
func TestClientFilteringHonorsCancellation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		call   func(context.Context, *Client) error
	}{
		{name: "GET", method: http.MethodGet, call: func(ctx context.Context, client *Client) error {
			_, err := client.FilteringStatus(ctx)

			return err
		}},
		{name: "POST", method: http.MethodPost, call: func(ctx context.Context, client *Client) error {
			return client.UpdateFilteringConfig(ctx, FilteringConfig{Enabled: nil, Interval: nil})
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			client := newFilteringTestClient(t, server, 4096)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			err := test.call(ctx, client)

			clientErr := requireClientError(t, err, ErrorKindRequest)
			assert.Equal(t, test.method, clientErr.Method)
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

// filteringReadRequestContracts returns filtering read request cases.
//
// Returns:
//   - contracts: The status and host-check request contracts.
func filteringReadRequestContracts() []filteringRequestContract {
	clientID := "client-42"
	queryType := "AAAA"

	return []filteringRequestContract{
		{
			name:         "status",
			method:       http.MethodGet,
			path:         "/api/control/filtering/status",
			query:        nil,
			wantBody:     "",
			responseBody: validFilteringStatusJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.FilteringStatus(ctx)

				return err
			},
		},
		{
			name:   "check host",
			method: http.MethodGet,
			path:   "/api/control/filtering/check_host",
			query: url.Values{
				filteringNameQueryKey: {filteringHostName},
				"client":              {clientID},
				"qtype":               {queryType},
			},
			wantBody:     "",
			responseBody: validFilteredHostJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.CheckFilteredHost(ctx, CheckHostRequest{
					Name:   filteringHostName,
					Client: &clientID,
					QType:  &queryType,
				})

				return err
			},
		},
	}
}

// filteringConfigRequestContracts returns the configuration request case.
//
// Returns:
//   - contracts: The configuration request contract.
func filteringConfigRequestContracts() []filteringRequestContract {
	falseValue := false

	return []filteringRequestContract{
		{
			name:         "update config",
			method:       http.MethodPost,
			path:         "/api/control/filtering/config",
			query:        nil,
			wantBody:     `{"enabled":false,"interval":12}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.UpdateFilteringConfig(ctx, FilteringConfig{
					Enabled:  &falseValue,
					Interval: new(int64(12)),
				})
			},
		},
	}
}

// filteringAddURLRequestContracts returns filtering add-URL request cases.
//
// Returns:
//   - contracts: The explicit, preserved-empty, and omitted-field request contracts.
func filteringAddURLRequestContracts() []filteringRequestContract {
	falseValue := false
	emptyValue := ""

	return []filteringRequestContract{
		{
			name:   "add URL",
			method: http.MethodPost,
			path:   filteringAddURLPath,
			query:  nil,
			wantBody: `{"name":"Example filter","url":"https://example.test/filter.txt",` +
				`"whitelist":false}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.AddFilteringURL(ctx, AddFilteringURLRequest{
					Name:      new(filteringTestFilterName),
					URL:       new(filteringTestFilterURL),
					Whitelist: &falseValue,
				})
			},
		},
		{
			name:         "add URL preserves empty strings and false",
			method:       http.MethodPost,
			path:         filteringAddURLPath,
			query:        nil,
			wantBody:     `{"name":"","url":"","whitelist":false}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.AddFilteringURL(ctx, AddFilteringURLRequest{
					Name:      &emptyValue,
					URL:       &emptyValue,
					Whitelist: &falseValue,
				})
			},
		},
		{
			name:         "add URL omits nil fields",
			method:       http.MethodPost,
			path:         filteringAddURLPath,
			query:        nil,
			wantBody:     filteringEmptyObject,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.AddFilteringURL(ctx, AddFilteringURLRequest{
					Name:      nil,
					URL:       nil,
					Whitelist: nil,
				})
			},
		},
	}
}

// filteringRemoveURLRequestContracts returns filtering remove-URL request cases.
//
// Returns:
//   - contracts: The explicit, preserved-empty, and omitted-field request contracts.
func filteringRemoveURLRequestContracts() []filteringRequestContract {
	falseValue := false
	emptyValue := ""

	return []filteringRequestContract{
		{
			name:         "remove URL",
			method:       http.MethodPost,
			path:         filteringRemoveURLPath,
			query:        nil,
			wantBody:     `{"url":"https://example.test/filter.txt"}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.RemoveFilteringURL(ctx, RemoveFilteringURLRequest{
					URL:       new(filteringTestFilterURL),
					Whitelist: nil,
				})
			},
		},
		{
			name:         "remove URL preserves empty string and false",
			method:       http.MethodPost,
			path:         filteringRemoveURLPath,
			query:        nil,
			wantBody:     `{"url":"","whitelist":false}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.RemoveFilteringURL(ctx, RemoveFilteringURLRequest{
					URL:       &emptyValue,
					Whitelist: &falseValue,
				})
			},
		},
		{
			name:         "remove URL omits nil fields",
			method:       http.MethodPost,
			path:         filteringRemoveURLPath,
			query:        nil,
			wantBody:     filteringEmptyObject,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.RemoveFilteringURL(ctx, RemoveFilteringURLRequest{
					URL:       nil,
					Whitelist: nil,
				})
			},
		},
	}
}

// filteringSetURLRequestContracts returns set-subscription request cases.
//
// Returns:
//   - contracts: The explicit-value and preserved-empty-value request contracts.
func filteringSetURLRequestContracts() []filteringRequestContract {
	trueValue := true
	falseValue := false
	emptyValue := ""

	return []filteringRequestContract{
		{
			name:         "set URL",
			method:       http.MethodPost,
			path:         filteringSetURLPath,
			query:        nil,
			wantBody:     filteringSetURLBody,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringURL(ctx, &SetFilteringURLRequest{
					Data: &FilteringURLData{
						Enabled: false,
						Name:    filteringTestFilterName,
						URL:     filteringTestFilterURL,
					},
					URL:       new(filteringTestOldURL),
					Whitelist: &trueValue,
				})
			},
		},
		{
			name:   "set URL preserves nested and outer empty values",
			method: http.MethodPost,
			path:   filteringSetURLPath,
			query:  nil,
			wantBody: `{"data":{"enabled":false,"name":"","url":""},` +
				`"url":"","whitelist":false}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringURL(ctx, &SetFilteringURLRequest{
					Data: &FilteringURLData{
						Enabled: false,
						Name:    "",
						URL:     "",
					},
					URL:       &emptyValue,
					Whitelist: &falseValue,
				})
			},
		},
	}
}

// filteringSetURLOmissionRequestContracts returns set-subscription omission cases.
//
// Returns:
//   - contracts: The omitted-optional-field and omitted-body request contracts.
func filteringSetURLOmissionRequestContracts() []filteringRequestContract {
	return []filteringRequestContract{
		{
			name:         "set URL omits nil optional fields",
			method:       http.MethodPost,
			path:         filteringSetURLPath,
			query:        nil,
			wantBody:     `{"data":{"enabled":false,"name":"Example filter","url":"https://example.test/filter.txt"}}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringURL(ctx, &SetFilteringURLRequest{
					Data: &FilteringURLData{
						Enabled: false,
						Name:    filteringTestFilterName,
						URL:     filteringTestFilterURL,
					},
					URL:       nil,
					Whitelist: nil,
				})
			},
		},
		{
			name:         "set URL omits optional body",
			method:       http.MethodPost,
			path:         filteringSetURLPath,
			query:        nil,
			wantBody:     "",
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringURL(ctx, nil)
			},
		},
	}
}

// filteringRefreshRequestContracts returns refresh request-presence cases.
//
// Returns:
//   - contracts: The explicit-false, omitted-body, and empty-object cases.
func filteringRefreshRequestContracts() []filteringRequestContract {
	falseValue := false

	return []filteringRequestContract{
		{
			name:         "refresh",
			method:       http.MethodPost,
			path:         filteringRefreshPath,
			query:        nil,
			wantBody:     `{"whitelist":false}`,
			responseBody: `{"updated":2}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RefreshFiltering(ctx, &RefreshFilteringRequest{
					Whitelist: &falseValue,
				})

				return err
			},
		},
		{
			name:         "refresh omits optional body",
			method:       http.MethodPost,
			path:         filteringRefreshPath,
			query:        nil,
			wantBody:     "",
			responseBody: filteringUpdatedZero,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RefreshFiltering(ctx, nil)

				return err
			},
		},
		{
			name:         "refresh sends empty object",
			method:       http.MethodPost,
			path:         filteringRefreshPath,
			query:        nil,
			wantBody:     filteringEmptyObject,
			responseBody: filteringUpdatedZero,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.RefreshFiltering(ctx, &RefreshFilteringRequest{
					Whitelist: nil,
				})

				return err
			},
		},
	}
}

// filteringSetRulesRequestContracts returns set-rules request-presence cases.
//
// Returns:
//   - contracts: The empty-list, omitted-body, and empty-object cases.
func filteringSetRulesRequestContracts() []filteringRequestContract {
	emptyRules := []string{}

	return []filteringRequestContract{
		{
			name:         "set rules preserves empty list",
			method:       http.MethodPost,
			path:         filteringSetRulesPath,
			query:        nil,
			wantBody:     `{"rules":[]}`,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringRules(ctx, &SetFilteringRulesRequest{
					Rules: &emptyRules,
				})
			},
		},
		{
			name:         "set rules omits optional body",
			method:       http.MethodPost,
			path:         filteringSetRulesPath,
			query:        nil,
			wantBody:     "",
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringRules(ctx, nil)
			},
		},
		{
			name:         "set rules sends empty object",
			method:       http.MethodPost,
			path:         filteringSetRulesPath,
			query:        nil,
			wantBody:     filteringEmptyObject,
			responseBody: "",
			call: func(ctx context.Context, client *Client) error {
				return client.SetFilteringRules(ctx, &SetFilteringRulesRequest{
					Rules: nil,
				})
			},
		},
	}
}

// testFilteringRequestContracts runs a group of filtering request contracts.
//
// Parameters:
//   - tests: The request contracts to exercise as parallel subtests.
func testFilteringRequestContracts(t *testing.T, tests []filteringRequestContract) {
	t.Helper()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testFilteringRequest(t, test)
		})
	}
}

// testFilteringRequest verifies one filtering request contract.
//
// Parameters:
//   - test: The request contract to exercise.
func testFilteringRequest(t *testing.T, test filteringRequestContract) {
	t.Helper()

	server, captured := newFilteringRequestServer(t, test.responseBody)
	client := newFilteringTestClient(t, server, 4096)

	err := test.call(t.Context(), client)

	require.NoError(t, err)
	assertFilteringRequest(t, test, <-captured)
}

// newFilteringRequestServer creates a server that captures one filtering request.
//
// Parameters:
//   - responseBody: The response body returned after capturing the request.
//
// Returns:
//   - server: The HTTP test server.
//   - captured: A channel containing the captured request metadata.
func newFilteringRequestServer(
	t *testing.T,
	responseBody string,
) (*httptest.Server, <-chan capturedFilteringRequest) {
	t.Helper()

	captured := make(chan capturedFilteringRequest, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err == nil {
			err = r.Body.Close()
		}
		if err != nil {
			return
		}

		username, password, hasAuth := r.BasicAuth()
		captured <- capturedFilteringRequest{
			body:        body,
			contentType: r.Header.Get("Content-Type"),
			method:      r.Method,
			path:        r.URL.Path,
			query:       r.URL.Query(),
			username:    username,
			password:    password,
			hasAuth:     hasAuth,
		}

		if responseBody != "" {
			w.Header().Set("Content-Type", testResponseMediaType)
		}

		writeBody(w, responseBody)
	}))

	return server, captured
}

// assertFilteringRequest verifies the captured request against one contract.
//
// Parameters:
//   - test: The expected request contract.
//   - request: The captured request metadata to inspect.
func assertFilteringRequest(
	t *testing.T,
	test filteringRequestContract,
	request capturedFilteringRequest,
) {
	t.Helper()

	assert.Equal(t, test.method, request.method)
	assert.Equal(t, test.path, request.path)

	if test.query == nil {
		assert.Empty(t, request.query)
	} else {
		assert.Equal(t, test.query, request.query)
	}

	assert.True(t, request.hasAuth)
	assert.Equal(t, "filtering-user", request.username)
	assert.Equal(t, "filtering-password", request.password)

	if test.method == http.MethodGet {
		assert.Empty(t, request.contentType)
	} else if request.contentType != testResponseMediaType {
		t.Errorf("content type = %q, want %q", request.contentType, testResponseMediaType)
	}
	if test.wantBody == "" {
		assert.Empty(t, request.body)

		return
	}

	assert.JSONEq(t, test.wantBody, string(request.body))
}

// filteringJSONServer creates a server that returns one JSON response body.
//
// Parameters:
//   - body: The JSON response body.
//
// Returns:
//   - server: The HTTP test server.
func filteringJSONServer(t *testing.T, body string) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", testResponseMediaType)
		writeBody(w, body)
	}))
}

// newFilteringTestClient creates a client bound to a filtering test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - client: The configured AdGuard client.
func newFilteringTestClient(t *testing.T, server *httptest.Server, limit int64) *Client {
	t.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth("filtering-user", "filtering-password"),
		WithUserAgent("filtering-client-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}
