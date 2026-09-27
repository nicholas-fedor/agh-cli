// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// queryLogIntegrationCall invokes one query-log operation.
type queryLogIntegrationCall func(context.Context, *adguard.Client) error

// queryLogIntegrationRequestContract describes one successful HTTP contract.
type queryLogIntegrationRequestContract struct {
	call                queryLogIntegrationCall
	method              string
	name                string
	path                string
	query               string
	requestBody         string
	responseBody        string
	responseContentType string
	status              int
}

// queryLogIntegrationRequestCapture contains the metadata from one HTTP request.
type queryLogIntegrationRequestCapture struct {
	accept        string
	body          []byte
	closeErr      error
	contentLength int64
	contentType   string
	hasAuth       bool
	method        string
	path          string
	password      string
	query         string
	readErr       error
	userAgent     string
	username      string
}

// queryLogIntegrationOperation describes one operation for transport-level tests.
type queryLogIntegrationOperation struct {
	call      queryLogIntegrationCall
	method    string
	name      string
	operation string
	path      string
}

// queryLogIntegrationResponseErrorCase describes one invalid JSON response.
type queryLogIntegrationResponseErrorCase struct {
	body            string
	call            queryLogIntegrationCall
	contentType     string
	kind            adguard.ErrorKind
	method          string
	name            string
	operation       string
	wantContentType string
}

const (
	// The loopback URL is routed by the in-memory test transport.
	queryLogIntegrationBaseURL = "http://127.0.0.1"
	// The expected Basic Auth username follows.
	queryLogIntegrationUsername = "query-log-integration-user"
	// The expected Basic Auth password follows.
	queryLogIntegrationPassword = "query-log-integration-password"
	// The expected client User-Agent follows.
	queryLogIntegrationUserAgent = "query-log-integration-client/1.0"
	// The request and response JSON media type follows.
	queryLogIntegrationJSONMediaType = "application/json"
	// A valid parameterized JSON response type follows.
	queryLogIntegrationResponseMediaType = "application/json; charset=utf-8"
	// The structured error response media type follows.
	queryLogIntegrationProblemMediaType = "application/problem+json; charset=utf-8"
	// The structured non-success response body follows.
	queryLogIntegrationErrorBody = `{"message":"query log request rejected"}`
	// A complete query-log configuration response follows.
	queryLogIntegrationConfigResponse = `{
		"enabled":true,
		"interval":86400000,
		"anonymize_client_ip":true,
		"ignored":["localhost","router.local"],
		"ignored_enabled":false
	}`
	// A complete query-log response follows.
	queryLogIntegrationLogResponse = `{
		"oldest":"2026-09-25T01:00:00Z",
		"data":[{
			"answer":[{"type":"A","ttl":0,"value":"192.0.2.1"}],
			"original_answer":[],
			"cached":false,
			"upstream":"https://dns.example/dns-query",
			"answer_dnssec":true,
			"client":"192.0.2.10",
			"client_id":"client-id",
			"client_info":{
				"disallowed":false,
				"disallowed_rule":"",
				"name":"desk",
				"whois":{"city":null,"country":"US","orgname":"Example Network"}
			},
			"client_proto":"dot",
			"ecs":"",
			"elapsedMs":"0.123",
			"question":{
				"class":"IN",
				"name":"example.org",
				"unicode_name":null,
				"type":"A"
			},
			"filterId":7,
			"rule":"||example.org^",
			"rules":[{"filter_list_id":7,"text":"||example.org^"}],
			"reason":"FilteredBlackList",
			"service_name":"",
			"status":"NOERROR",
			"time":"2026-09-25T01:01:00Z"
		}]
	}`
)

// TestQueryLogIntegrationRequestContracts verifies every query-log request contract.
func TestQueryLogIntegrationRequestContracts(t *testing.T) {
	t.Parallel()

	contracts := queryLogIntegrationRequestContracts()
	for index := range contracts {
		test := &contracts[index]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runQueryLogIntegrationRequestContract(t, test)
		})
	}
}

// TestQueryLogIntegrationDecodesJSONResponses verifies complete query-log response models.
func TestQueryLogIntegrationDecodesJSONResponses(t *testing.T) {
	t.Parallel()

	t.Run("query log", testQueryLogIntegrationLogResponse)
	t.Run("configuration", testQueryLogIntegrationConfigResponse)
}

// TestQueryLogIntegrationPreservesOptionalFields verifies omitted, null, and explicit values.
func TestQueryLogIntegrationPreservesOptionalFields(t *testing.T) {
	t.Parallel()

	t.Run("query log", testQueryLogIntegrationOptionalLogFields)
	t.Run("configuration", testQueryLogIntegrationOptionalConfigField)
}

// TestQueryLogIntegrationRejectsMalformedInput verifies local request validation.
func TestQueryLogIntegrationRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		call      queryLogIntegrationCall
		method    string
		name      string
		operation string
	}{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.QueryLog(ctx, &adguard.QueryLogRequest{
					Reasons: []adguard.FilteringReason{adguard.FilteringReason("FutureReason")},
				})

				return err
			},
			method:    http.MethodGet,
			name:      "invalid reason",
			operation: "query_log",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutQueryLogConfig(ctx, adguard.QueryLogConfig{})
			},
			method:    http.MethodPut,
			name:      "missing ignored list",
			operation: "put_query_log_config",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			client := newQueryLogIntegrationClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireQueryLogIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			require.Error(t, clientErr.Err)
			assert.Zero(t, requests.Load())
		})
	}
}

// TestQueryLogIntegrationReturnsStructuredStatusErrors verifies HTTP error metadata.
func TestQueryLogIntegrationReturnsStructuredStatusErrors(t *testing.T) {
	t.Parallel()

	for _, operation := range queryLogIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			runQueryLogIntegrationStatusError(t, operation)
		})
	}
}

// TestQueryLogIntegrationReturnsStructuredResponseErrors verifies JSON contract errors.
func TestQueryLogIntegrationReturnsStructuredResponseErrors(t *testing.T) {
	t.Parallel()

	for _, test := range queryLogIntegrationResponseErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogIntegrationResponseServer(t, test.contentType, test.body)
			client := newQueryLogIntegrationClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireQueryLogIntegrationError(t, err, test.kind)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.wantContentType, clientErr.ContentType)
			require.Error(t, clientErr.Err)
		})
	}
}

// TestQueryLogIntegrationEnforcesResponseLimits verifies bounded responses for every operation.
func TestQueryLogIntegrationEnforcesResponseLimits(t *testing.T) {
	t.Parallel()

	const limit = int64(3)

	for _, operation := range queryLogIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogIntegrationResponseServer(t, queryLogIntegrationJSONMediaType, "overflow")
			client := newQueryLogIntegrationClient(t, server, limit)

			err := operation.call(t.Context(), client)

			clientErr := requireQueryLogIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
			//nolint:testifylint // encoded-compare: Exact HTTP media-type equality is required.
			assert.Equal(t, queryLogIntegrationJSONMediaType, clientErr.ContentType)
			assert.Equal(t, limit, clientErr.Limit)
		})
	}
}

// TestQueryLogIntegrationHonorsCancellation verifies cancellation for every operation.
func TestQueryLogIntegrationHonorsCancellation(t *testing.T) {
	t.Parallel()

	for _, operation := range queryLogIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			client := newQueryLogIntegrationClient(t, server, 4096)
			ctx, cancel := context.WithCancel(t.Context())

			cancel()

			err := operation.call(ctx, client)

			clientErr := requireQueryLogIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			require.ErrorIs(t, err, context.Canceled)
			assert.Zero(t, requests.Load())
		})
	}
}

// testQueryLogIntegrationLogResponse verifies complete query-log decoding.
func testQueryLogIntegrationLogResponse(t *testing.T) {
	t.Helper()
	t.Parallel()

	server := newQueryLogIntegrationResponseServer(
		t,
		queryLogIntegrationResponseMediaType,
		queryLogIntegrationLogResponse,
	)
	client := newQueryLogIntegrationClient(t, server, 16<<10)

	log, err := client.QueryLog(t.Context(), nil)

	require.NoError(t, err)
	require.NotNil(t, log)
	require.NotNil(t, log.Oldest)
	assert.Equal(t, "2026-09-25T01:00:00Z", *log.Oldest)
	require.NotNil(t, log.Data)
	require.Len(t, *log.Data, 1)

	entry := (*log.Data)[0]
	require.NotNil(t, entry.Answer)
	require.Len(t, *entry.Answer, 1)
	require.NotNil(t, (*entry.Answer)[0])
	require.NotNil(t, (*entry.Answer)[0].TTL)
	assert.Zero(t, *(*entry.Answer)[0].TTL)
	require.NotNil(t, (*entry.Answer)[0].Type)
	assert.Equal(t, "A", *(*entry.Answer)[0].Type)
	require.NotNil(t, (*entry.Answer)[0].Value)
	assert.Equal(t, "192.0.2.1", *(*entry.Answer)[0].Value)
	require.NotNil(t, entry.OriginalAnswer)
	assert.Empty(t, *entry.OriginalAnswer)
	require.NotNil(t, entry.Cached)
	assert.False(t, *entry.Cached)
	require.NotNil(t, entry.Upstream)
	assert.Equal(t, "https://dns.example/dns-query", *entry.Upstream)
	require.NotNil(t, entry.AnswerDNSSEC)
	assert.True(t, *entry.AnswerDNSSEC)
	require.NotNil(t, entry.Client)
	assert.Equal(t, "192.0.2.10", *entry.Client)
	require.NotNil(t, entry.ClientID)
	assert.Equal(t, "client-id", *entry.ClientID)
	require.NotNil(t, entry.ClientInfo)
	assert.False(t, entry.ClientInfo.Disallowed)
	assert.Empty(t, entry.ClientInfo.DisallowedRule)
	assert.Equal(t, "desk", entry.ClientInfo.Name)
	require.NotNil(t, entry.ClientInfo.Whois)
	assert.Nil(t, entry.ClientInfo.Whois.City)
	require.NotNil(t, entry.ClientInfo.Whois.Country)
	assert.Equal(t, "US", *entry.ClientInfo.Whois.Country)
	require.NotNil(t, entry.ClientInfo.Whois.Organization)
	assert.Equal(t, "Example Network", *entry.ClientInfo.Whois.Organization)
	require.NotNil(t, entry.ClientProtocol)
	assert.Equal(t, "dot", *entry.ClientProtocol)
	require.NotNil(t, entry.ECS)
	assert.Empty(t, *entry.ECS)
	require.NotNil(t, entry.ElapsedMS)
	assert.Equal(t, "0.123", *entry.ElapsedMS)
	require.NotNil(t, entry.Question)
	require.NotNil(t, entry.Question.Class)
	assert.Equal(t, "IN", *entry.Question.Class)
	require.NotNil(t, entry.Question.Name)
	assert.Equal(t, "example.org", *entry.Question.Name)
	assert.Nil(t, entry.Question.UnicodeName)
	require.NotNil(t, entry.Question.Type)
	assert.Equal(t, "A", *entry.Question.Type)
	require.NotNil(t, entry.FilterID)
	assert.Equal(t, int32(7), *entry.FilterID)
	require.NotNil(t, entry.Rule)
	assert.Equal(t, "||example.org^", *entry.Rule)
	require.NotNil(t, entry.Rules)
	require.Len(t, *entry.Rules, 1)
	require.NotNil(t, (*entry.Rules)[0])
	require.NotNil(t, (*entry.Rules)[0].FilterListID)
	assert.Equal(t, int64(7), *(*entry.Rules)[0].FilterListID)
	require.NotNil(t, (*entry.Rules)[0].Text)
	assert.Equal(t, "||example.org^", *(*entry.Rules)[0].Text)
	require.NotNil(t, entry.Reason)
	assert.Equal(t, adguard.FilteringReasonFilteredBlackList, *entry.Reason)
	require.NotNil(t, entry.ServiceName)
	assert.Empty(t, *entry.ServiceName)
	require.NotNil(t, entry.Status)
	assert.Equal(t, "NOERROR", *entry.Status)
	require.NotNil(t, entry.Time)
	assert.Equal(t, "2026-09-25T01:01:00Z", *entry.Time)
}

// testQueryLogIntegrationConfigResponse verifies complete configuration decoding.
func testQueryLogIntegrationConfigResponse(t *testing.T) {
	t.Helper()
	t.Parallel()

	server := newQueryLogIntegrationResponseServer(
		t,
		queryLogIntegrationResponseMediaType,
		queryLogIntegrationConfigResponse,
	)
	client := newQueryLogIntegrationClient(t, server, 4096)

	config, err := client.GetQueryLogConfig(t.Context())

	require.NoError(t, err)
	require.NotNil(t, config)
	assert.True(t, config.Enabled)
	assert.InDelta(t, float64(86_400_000), config.Interval, 0)
	assert.True(t, config.AnonymizeClientIP)
	assert.Equal(t, []string{"localhost", "router.local"}, config.Ignored)
	require.NotNil(t, config.IgnoredEnabled)
	assert.False(t, *config.IgnoredEnabled)
}

// testQueryLogIntegrationOptionalLogFields verifies query-log pointer presence semantics.
func testQueryLogIntegrationOptionalLogFields(t *testing.T) {
	t.Helper()
	t.Parallel()

	tests := []struct {
		body      string
		name      string
		wantEmpty bool
	}{
		{name: "absent", body: `{}`},
		{name: "null", body: `{"oldest":null,"data":null}`},
		{name: "empty", body: `{"oldest":"","data":[]}`, wantEmpty: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogIntegrationResponseServer(t, queryLogIntegrationJSONMediaType, test.body)
			client := newQueryLogIntegrationClient(t, server, 4096)

			log, err := client.QueryLog(t.Context(), &adguard.QueryLogRequest{})

			require.NoError(t, err)
			require.NotNil(t, log)
			assert.Equal(t, test.wantEmpty, log.Oldest != nil)
			assert.Equal(t, test.wantEmpty, log.Data != nil)

			if test.wantEmpty {
				require.NotNil(t, log.Oldest)
				require.NotNil(t, log.Data)
				assert.Empty(t, *log.Oldest)
				assert.Empty(t, *log.Data)
			}
		})
	}
}

// testQueryLogIntegrationOptionalConfigField verifies optional boolean presence semantics.
func testQueryLogIntegrationOptionalConfigField(t *testing.T) {
	t.Helper()
	t.Parallel()

	tests := []struct {
		body string
		name string
		want *bool
	}{
		{name: "absent", body: `{"enabled":true,"interval":0,"anonymize_client_ip":false,"ignored":[]}`},
		{
			name: "null",
			body: `{"enabled":true,"interval":0,"anonymize_client_ip":false,"ignored":[],` +
				`"ignored_enabled":null}`,
		},
		{
			name: "false",
			body: `{"enabled":true,"interval":0,"anonymize_client_ip":false,"ignored":[],` +
				`"ignored_enabled":false}`,
			want: new(false),
		},
		{
			name: "true",
			body: `{"enabled":true,"interval":0,"anonymize_client_ip":false,"ignored":[],` +
				`"ignored_enabled":true}`,
			want: new(true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogIntegrationResponseServer(t, queryLogIntegrationJSONMediaType, test.body)
			client := newQueryLogIntegrationClient(t, server, 4096)

			config, err := client.GetQueryLogConfig(t.Context())

			require.NoError(t, err)
			require.NotNil(t, config)

			if test.want == nil {
				assert.Nil(t, config.IgnoredEnabled)

				return
			}

			require.NotNil(t, config.IgnoredEnabled)
			assert.Equal(t, *test.want, *config.IgnoredEnabled)
		})
	}
}

// queryLogIntegrationRequestContracts returns every successful query-log HTTP contract.
//
// Returns:
//   - The nil, empty, fully populated, clear, read-configuration, and update cases.
func queryLogIntegrationRequestContracts() []queryLogIntegrationRequestContract {
	olderThan := "2026-09-25T00:00:00Z"
	offset := int32(0)
	limit := int32(25)
	search := "example.org"

	return []queryLogIntegrationRequestContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.QueryLog(ctx, nil)

				return err
			},
			method:              http.MethodGet,
			name:                "query log without request",
			path:                "/control/querylog",
			query:               "",
			requestBody:         "",
			responseBody:        `{}`,
			responseContentType: queryLogIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.QueryLog(ctx, &adguard.QueryLogRequest{})

				return err
			},
			method:              http.MethodGet,
			name:                "query log with empty request",
			path:                "/control/querylog",
			query:               "",
			requestBody:         "",
			responseBody:        `{"oldest":null,"data":null}`,
			responseContentType: queryLogIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.QueryLog(ctx, &adguard.QueryLogRequest{
					OlderThan: &olderThan,
					Offset:    &offset,
					Limit:     &limit,
					Search:    &search,
					Reasons: []adguard.FilteringReason{
						adguard.FilteringReasonFilteredBlackList,
						adguard.FilteringReasonRewrite,
					},
				})

				return err
			},
			method: http.MethodGet,
			name:   "query log with every query value",
			path:   "/control/querylog",
			query: "limit=25&offset=0&older_than=2026-09-25T00%3A00%3A00Z&" +
				"reason=FilteredBlackList&reason=Rewrite&search=example.org",
			requestBody:         "",
			responseBody:        `{"oldest":"","data":[]}`,
			responseContentType: queryLogIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.QueryLogClear(ctx)
			},
			method:              http.MethodPost,
			name:                "clear",
			path:                "/control/querylog_clear",
			query:               "",
			requestBody:         "",
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetQueryLogConfig(ctx)

				return err
			},
			method:              http.MethodGet,
			name:                "read configuration",
			path:                "/control/querylog/config",
			query:               "",
			requestBody:         "",
			responseBody:        queryLogIntegrationConfigResponse,
			responseContentType: queryLogIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutQueryLogConfig(ctx, adguard.QueryLogConfig{
					Enabled:           true,
					Interval:          86_400_000,
					AnonymizeClientIP: true,
					Ignored:           []string{"localhost"},
					IgnoredEnabled:    nil,
				})
			},
			method: http.MethodPut,
			name:   "update configuration without optional field",
			path:   "/control/querylog/config/update",
			query:  "",
			requestBody: `{"enabled":true,"interval":86400000,` +
				`"anonymize_client_ip":true,"ignored":["localhost"]}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutQueryLogConfig(ctx, adguard.QueryLogConfig{
					Enabled:           false,
					Interval:          0,
					AnonymizeClientIP: false,
					Ignored:           []string{},
					IgnoredEnabled:    new(false),
				})
			},
			method: http.MethodPut,
			name:   "update configuration with explicit false",
			path:   "/control/querylog/config/update",
			query:  "",
			requestBody: `{"enabled":false,"interval":0,` +
				`"anonymize_client_ip":false,"ignored":[],"ignored_enabled":false}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutQueryLogConfig(ctx, adguard.QueryLogConfig{
					Enabled:           true,
					Interval:          3_600_000,
					AnonymizeClientIP: true,
					Ignored:           []string{"router.local"},
					IgnoredEnabled:    new(true),
				})
			},
			method: http.MethodPut,
			name:   "update configuration with explicit true",
			path:   "/control/querylog/config/update",
			query:  "",
			requestBody: `{"enabled":true,"interval":3600000,` +
				`"anonymize_client_ip":true,"ignored":["router.local"],"ignored_enabled":true}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
	}
}

// queryLogIntegrationOperations returns every query-log operation for transport tests.
//
// Returns:
//   - The read, clear, configuration-read, and configuration-update operations.
func queryLogIntegrationOperations() []queryLogIntegrationOperation {
	return []queryLogIntegrationOperation{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.QueryLog(ctx, nil)

				return err
			},
			method:    http.MethodGet,
			name:      "query log",
			operation: "query_log",
			path:      "/control/querylog",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.QueryLogClear(ctx)
			},
			method:    http.MethodPost,
			name:      "clear",
			operation: "query_log_clear",
			path:      "/control/querylog_clear",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetQueryLogConfig(ctx)

				return err
			},
			method:    http.MethodGet,
			name:      "read configuration",
			operation: "get_query_log_config",
			path:      "/control/querylog/config",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutQueryLogConfig(ctx, adguard.QueryLogConfig{Ignored: []string{}})
			},
			method:    http.MethodPut,
			name:      "update configuration",
			operation: "put_query_log_config",
			path:      "/control/querylog/config/update",
		},
	}
}

// queryLogIntegrationResponseErrorCases returns invalid query-log JSON response cases.
//
// Returns:
//   - Malformed, empty, null, schema-invalid, and media-type response cases.
func queryLogIntegrationResponseErrorCases() []queryLogIntegrationResponseErrorCase {
	queryLogCall := func(ctx context.Context, client *adguard.Client) error {
		_, err := client.QueryLog(ctx, nil)

		return err
	}
	configCall := func(ctx context.Context, client *adguard.Client) error {
		_, err := client.GetQueryLogConfig(ctx)

		return err
	}

	return []queryLogIntegrationResponseErrorCase{
		{
			body:        `{"data":`,
			call:        queryLogCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "malformed query log",
			operation:   "query_log",
		},
		{
			body:        "",
			call:        queryLogCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "empty query log response",
			operation:   "query_log",
		},
		{
			body:        "null",
			call:        queryLogCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "null query log",
			operation:   "query_log",
		},
		{
			body:        `{"data":[{"reason":"FutureReason"}]}`,
			call:        queryLogCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "invalid response reason",
			operation:   "query_log",
		},
		{
			body:        `{"data":[{"client_info":{"disallowed":false}}]}`,
			call:        queryLogCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "incomplete client information",
			operation:   "query_log",
		},
		{
			body:            `{}`,
			call:            queryLogCall,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			method:          http.MethodGet,
			name:            "query log media type",
			operation:       "query_log",
			wantContentType: "text/plain",
		},
		{
			body:        `{"enabled":`,
			call:        configCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "malformed configuration",
			operation:   "get_query_log_config",
		},
		{
			body:        "",
			call:        configCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "empty configuration response",
			operation:   "get_query_log_config",
		},
		{
			body:        "null",
			call:        configCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "null configuration",
			operation:   "get_query_log_config",
		},
		{
			body:        `{"enabled":true,"interval":1,"anonymize_client_ip":true}`,
			call:        configCall,
			contentType: queryLogIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "missing required configuration field",
			operation:   "get_query_log_config",
		},
		{
			body:            queryLogIntegrationConfigResponse,
			call:            configCall,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			method:          http.MethodGet,
			name:            "configuration media type",
			operation:       "get_query_log_config",
			wantContentType: "text/plain",
		},
	}
}

// runQueryLogIntegrationRequestContract verifies one successful request contract.
//
// Parameters:
//   - contract: The request and response contract to exercise.
func runQueryLogIntegrationRequestContract(t *testing.T, contract *queryLogIntegrationRequestContract) {
	t.Helper()

	captured := make(chan queryLogIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureQueryLogIntegrationRequest(r)

		writeQueryLogIntegrationResponse(
			w,
			contract.responseContentType,
			contract.status,
			contract.responseBody,
		)
	}))
	client := newQueryLogIntegrationClient(t, server, 16<<10)

	err := contract.call(t.Context(), client)

	require.NoError(t, err)
	assertQueryLogIntegrationRequest(t, contract, <-captured)
}

// runQueryLogIntegrationStatusError verifies one structured non-success response.
//
// Parameters:
//   - operation: The query-log operation to exercise.
func runQueryLogIntegrationStatusError(t *testing.T, operation queryLogIntegrationOperation) {
	t.Helper()

	captured := make(chan queryLogIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureQueryLogIntegrationRequest(r)

		writeQueryLogIntegrationResponse(
			w,
			queryLogIntegrationProblemMediaType,
			http.StatusUnprocessableEntity,
			queryLogIntegrationErrorBody,
		)
	}))
	client := newQueryLogIntegrationClient(t, server, 4096)

	err := operation.call(t.Context(), client)

	clientErr := requireQueryLogIntegrationError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, operation.operation, clientErr.Operation)
	assert.Equal(t, operation.method, clientErr.Method)
	assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
	assert.Equal(t, "422 Unprocessable Entity", clientErr.Status)
	assert.Equal(t, queryLogIntegrationProblemMediaType, clientErr.ContentType)
	assert.JSONEq(t, queryLogIntegrationErrorBody, string(clientErr.Body))
	assert.NoError(t, clientErr.Err)

	request := <-captured
	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, operation.method, request.method)
	assert.Equal(t, operation.path, request.path)
	assert.Empty(t, request.query)
	assertQueryLogIntegrationAuthentication(t, request)
}

// newQueryLogIntegrationResponseServer creates a fixed query-log response server.
//
// Parameters:
//   - contentType: The response media type.
//   - body: The response body, or an empty string for no body.
//
// Returns:
//   - server: The HTTP test server.
func newQueryLogIntegrationResponseServer(
	t *testing.T,
	contentType string,
	body string,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeQueryLogIntegrationResponse(w, contentType, http.StatusOK, body)
	}))
}

// newQueryLogIntegrationClient creates a concrete client bound to a test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum accepted response body size.
//
// Returns:
//   - client: The configured AdGuard client.
func newQueryLogIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		queryLogIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(queryLogIntegrationUsername, queryLogIntegrationPassword),
		adguard.WithUserAgent(queryLogIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// captureQueryLogIntegrationRequest reads and records one query-log request.
//
// Parameters:
//   - request: The HTTP request captured by the test server.
//
// Returns:
//   - capture: The request metadata and body-consumption errors.
func captureQueryLogIntegrationRequest(
	request *http.Request,
) queryLogIntegrationRequestCapture {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	username, password, hasAuth := request.BasicAuth()

	return queryLogIntegrationRequestCapture{
		accept:        request.Header.Get("Accept"),
		body:          body,
		closeErr:      closeErr,
		contentLength: request.ContentLength,
		contentType:   request.Header.Get("Content-Type"),
		hasAuth:       hasAuth,
		method:        request.Method,
		path:          request.URL.Path,
		password:      password,
		query:         request.URL.RawQuery,
		readErr:       readErr,
		userAgent:     request.Header.Get("User-Agent"),
		username:      username,
	}
}

// assertQueryLogIntegrationRequest verifies one captured request contract.
//
// Parameters:
//   - contract: The expected request contract.
//   - request: The captured request metadata.
func assertQueryLogIntegrationRequest(
	t *testing.T,
	contract *queryLogIntegrationRequestContract,
	request queryLogIntegrationRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, contract.method, request.method)
	assert.Equal(t, contract.path, request.path)
	assert.Equal(t, contract.query, request.query)
	//nolint:testifylint // encoded-compare: Exact HTTP header equality is required.
	assert.Equal(t, queryLogIntegrationJSONMediaType, request.accept)
	assert.Equal(t, queryLogIntegrationUserAgent, request.userAgent)
	assertQueryLogIntegrationAuthentication(t, request)

	if contract.requestBody == "" {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.body)
		assert.Empty(t, request.contentType)

		return
	}

	assert.Positive(t, request.contentLength)
	//nolint:testifylint // encoded-compare: Exact HTTP header equality is required.
	assert.Equal(t, queryLogIntegrationJSONMediaType, request.contentType)
	assert.JSONEq(t, contract.requestBody, string(request.body))
}

// assertQueryLogIntegrationAuthentication verifies exact Basic Auth credentials.
//
// Parameters:
//   - request: The captured request metadata.
func assertQueryLogIntegrationAuthentication(
	t *testing.T,
	request queryLogIntegrationRequestCapture,
) {
	t.Helper()

	assert.True(t, request.hasAuth)
	assert.Equal(t, queryLogIntegrationUsername, request.username)
	assert.Equal(t, queryLogIntegrationPassword, request.password)
}

// writeQueryLogIntegrationResponse writes one complete HTTP response.
//
// Parameters:
//   - writer: The response writer receiving the response.
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP status code.
//   - body: The response body, or an empty string for no body.
func writeQueryLogIntegrationResponse(
	writer http.ResponseWriter,
	contentType string,
	status int,
	body string,
) {
	if contentType != "" {
		writer.Header().Set("Content-Type", contentType)
	}

	writer.WriteHeader(status)

	if body == "" {
		return
	}

	_, err := io.WriteString(writer, body)
	if err != nil {
		return
	}
}

// requireQueryLogIntegrationError extracts a structured query-log client error.
//
// Parameters:
//   - err: The operation error to inspect.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireQueryLogIntegrationError(
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
