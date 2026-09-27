// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// QueryLogBaseURL is the base URL routed by the in-memory transport.
	queryLogBaseURL = "http://127.0.0.1/api/"
	// QueryLogUsername is the Basic authentication username for query-log fixtures.
	queryLogUsername = "query-log-user"
	// QueryLogPassword is the Basic authentication password for query-log fixtures.
	queryLogPassword = "query-log-password"
	// QueryLogUserAgent is the expected client User-Agent for query-log fixtures.
	queryLogUserAgent = "agh-cli-query-log-test/1.0"
	// QueryLogResponseLimit is the normal query-log response-body limit.
	queryLogResponseLimit = int64(16 << 10)
	// QueryLogResponseJSON is the complete query-log search response fixture.
	queryLogResponseJSON = `{
		"oldest":"2026-09-25T01:00:00Z",
		"data":[{
			"answer":[{"type":"A","ttl":0,"value":"192.0.2.1"}],
			"original_answer":[null],
			"cached":false,
			"upstream":"https://dns.example/dns-query",
			"answer_dnssec":false,
			"client":"192.0.2.10",
			"client_id":"",
			"client_info":{
				"disallowed":false,
				"disallowed_rule":"",
				"name":"",
				"whois":{"city":null,"country":"","orgname":"Example Network"}
			},
			"client_proto":"dot",
			"ecs":"",
			"elapsedMs":"0",
			"question":{
				"class":"IN",
				"name":"example.org",
				"unicode_name":null,
				"type":"A"
			},
			"filterId":0,
			"rule":"",
			"rules":[{"filter_list_id":0,"text":""}],
			"reason":"NotFilteredNotFound",
			"service_name":"",
			"status":"NOERROR",
			"time":"2026-09-25T01:01:00Z",
			"future_field":true
		}]
	}`
	// QueryLogConfigJSON is the complete query-log configuration fixture.
	queryLogConfigJSON = `{
		"enabled":false,
		"interval":0,
		"anonymize_client_ip":false,
		"ignored":[],
		"ignored_enabled":null
	}`
)

// The concrete client satisfies the public query-log service contract.
var _ QueryLogService = (*Client)(nil)

// TestClientQueryLogRequestAndResponse verifies the pinned query-log search
// request and complete response contract.
func TestClientQueryLogRequestAndResponse(t *testing.T) {
	t.Parallel()

	olderThan := ""
	offset := int32(0)
	limit := int32(0)
	search := "example.org"

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, queryLogUsername, username)
		assert.Equal(t, queryLogPassword, password)
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/querylog", r.URL.Path)
		assert.Equal(
			t,
			"limit=0&offset=0&older_than=&reason=FilteredBlackList&reason=Rewrite&"+
				"search=example.org",
			r.URL.RawQuery,
		)
		assert.Equal(t, "application/json", r.Header.Get("Accept"))
		assert.Equal(t, queryLogUserAgent, r.Header.Get("User-Agent"))
		assert.Zero(t, r.ContentLength)
		assert.Empty(t, r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)
		assert.Empty(t, body)

		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		_, err = w.Write([]byte(queryLogResponseJSON))
		assert.NoError(t, err)
	}))
	client := newQueryLogTestClient(t, server, int64(len(queryLogResponseJSON)))

	log, err := client.QueryLog(t.Context(), &QueryLogRequest{
		OlderThan: &olderThan,
		Offset:    &offset,
		Limit:     &limit,
		Search:    &search,
		Reasons: []FilteringReason{
			FilteringReasonFilteredBlackList,
			FilteringReasonRewrite,
		},
	})

	require.NoError(t, err)
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
	require.Len(t, *entry.OriginalAnswer, 1)
	assert.Nil(t, (*entry.OriginalAnswer)[0])
	require.NotNil(t, entry.Cached)
	assert.False(t, *entry.Cached)
	require.NotNil(t, entry.Upstream)
	assert.Equal(t, "https://dns.example/dns-query", *entry.Upstream)
	require.NotNil(t, entry.AnswerDNSSEC)
	assert.False(t, *entry.AnswerDNSSEC)
	require.NotNil(t, entry.Client)
	assert.Equal(t, "192.0.2.10", *entry.Client)
	require.NotNil(t, entry.ClientID)
	assert.Empty(t, *entry.ClientID)
	require.NotNil(t, entry.ClientInfo)
	assert.False(t, entry.ClientInfo.Disallowed)
	assert.Empty(t, entry.ClientInfo.DisallowedRule)
	assert.Empty(t, entry.ClientInfo.Name)
	require.NotNil(t, entry.ClientInfo.Whois)
	assert.Nil(t, entry.ClientInfo.Whois.City)
	require.NotNil(t, entry.ClientInfo.Whois.Country)
	assert.Empty(t, *entry.ClientInfo.Whois.Country)
	require.NotNil(t, entry.ClientInfo.Whois.Organization)
	assert.Equal(t, "Example Network", *entry.ClientInfo.Whois.Organization)
	require.NotNil(t, entry.ClientProtocol)
	assert.Equal(t, "dot", *entry.ClientProtocol)
	require.NotNil(t, entry.ECS)
	assert.Empty(t, *entry.ECS)
	require.NotNil(t, entry.ElapsedMS)
	assert.Equal(t, "0", *entry.ElapsedMS)
	require.NotNil(t, entry.Question)
	require.NotNil(t, entry.Question.Class)
	assert.Equal(t, "IN", *entry.Question.Class)
	require.NotNil(t, entry.Question.Name)
	assert.Equal(t, "example.org", *entry.Question.Name)
	assert.Nil(t, entry.Question.UnicodeName)
	require.NotNil(t, entry.Question.Type)
	assert.Equal(t, "A", *entry.Question.Type)
	require.NotNil(t, entry.FilterID)
	assert.Zero(t, *entry.FilterID)
	require.NotNil(t, entry.Rule)
	assert.Empty(t, *entry.Rule)
	require.NotNil(t, entry.Rules)
	require.Len(t, *entry.Rules, 1)
	require.NotNil(t, (*entry.Rules)[0].FilterListID)
	assert.Zero(t, *(*entry.Rules)[0].FilterListID)
	require.NotNil(t, (*entry.Rules)[0].Text)
	assert.Empty(t, *(*entry.Rules)[0].Text)
	require.NotNil(t, entry.Reason)
	assert.Equal(t, FilteringReasonNotFilteredNotFound, *entry.Reason)
	require.NotNil(t, entry.ServiceName)
	assert.Empty(t, *entry.ServiceName)
	require.NotNil(t, entry.Status)
	assert.Equal(t, "NOERROR", *entry.Status)
	require.NotNil(t, entry.Time)
	assert.Equal(t, "2026-09-25T01:01:00Z", *entry.Time)
}

// TestClientQueryLogOptionalPresence verifies optional query-log response field
// presence and empty-value preservation.
func TestClientQueryLogOptionalPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		request   *QueryLogRequest
		body      string
		wantOld   bool
		wantData  bool
		wantEmpty bool
	}{
		{name: "absent", body: `{}`},
		{
			name:    "null",
			request: &QueryLogRequest{},
			body:    `{"oldest":null,"data":null}`,
		},
		{
			name:      "empty values",
			request:   &QueryLogRequest{},
			body:      `{"oldest":"","data":[]}`,
			wantOld:   true,
			wantData:  true,
			wantEmpty: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogResponseServer(t, "application/json", test.body, http.StatusOK)
			client := newQueryLogTestClient(t, server, queryLogResponseLimit)

			log, err := client.QueryLog(t.Context(), test.request)

			require.NoError(t, err)
			require.NotNil(t, log)
			assert.Equal(t, test.wantOld, log.Oldest != nil)
			assert.Equal(t, test.wantData, log.Data != nil)

			if test.wantEmpty {
				assert.Empty(t, *log.Oldest)
				assert.Empty(t, *log.Data)
			}
		})
	}
}

// TestClientGetQueryLogConfig verifies the pinned configuration read request
// and complete response contract.
func TestClientGetQueryLogConfig(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/api/control/querylog/config", r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Zero(t, r.ContentLength)
		assert.Empty(t, r.Header.Get("Content-Type"))
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(queryLogConfigJSON))
		assert.NoError(t, err)
	}))
	client := newQueryLogTestClient(t, server, int64(len(queryLogConfigJSON)))

	config, err := client.GetQueryLogConfig(t.Context())

	require.NoError(t, err)
	assert.False(t, config.Enabled)
	assert.Zero(t, config.Interval)
	assert.False(t, config.AnonymizeClientIP)
	assert.Empty(t, config.Ignored)
	assert.NotNil(t, config.Ignored)
	assert.Nil(t, config.IgnoredEnabled)
}

// TestClientGetQueryLogConfigOptionalPresence verifies the optional
// ignored-enabled configuration field across absent, null, false, and true.
func TestClientGetQueryLogConfigOptionalPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *bool
	}{
		{
			name: "absent",
			body: `{"enabled":true,"interval":1,"anonymize_client_ip":true,"ignored":[]}`,
		},
		{
			name: "null",
			body: `{"enabled":true,"interval":1,"anonymize_client_ip":true,` +
				`"ignored":[],"ignored_enabled":null}`,
		},
		{
			name: "false",
			body: `{"enabled":true,"interval":1,"anonymize_client_ip":true,` +
				`"ignored":[],"ignored_enabled":false}`,
			want: new(false),
		},
		{
			name: "true",
			body: `{"enabled":true,"interval":1,"anonymize_client_ip":true,` +
				`"ignored":[],"ignored_enabled":true}`,
			want: new(true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogResponseServer(t, "application/json", test.body, http.StatusOK)
			client := newQueryLogTestClient(t, server, queryLogResponseLimit)

			config, err := client.GetQueryLogConfig(t.Context())

			require.NoError(t, err)

			if test.want == nil {
				assert.Nil(t, config.IgnoredEnabled)
			} else {
				require.NotNil(t, config.IgnoredEnabled)
				assert.Equal(t, *test.want, *config.IgnoredEnabled)
			}
		})
	}
}

// TestClientGetQueryLogConfigRejectsWrongContentType verifies that a
// non-JSON configuration response is rejected as a media-type failure.
func TestClientGetQueryLogConfigRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	server := newQueryLogResponseServer(t, "text/plain", queryLogConfigJSON, http.StatusOK)
	client := newQueryLogTestClient(t, server, queryLogResponseLimit)

	_, err := client.GetQueryLogConfig(t.Context())

	clientErr := requireQueryLogError(t, err, ErrorKindContentType)
	assert.Equal(t, "get_query_log_config", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
}

// TestClientQueryLogRejectsInvalidRequestReason verifies that an unknown
// filtering reason is rejected before any request reaches the server.
func TestClientQueryLogRejectsInvalidRequestReason(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newQueryLogTestClient(t, server, queryLogResponseLimit)

	_, err := client.QueryLog(t.Context(), &QueryLogRequest{
		Reasons: []FilteringReason{"FutureReason"},
	})

	clientErr := requireQueryLogError(t, err, ErrorKindRequest)
	assert.Equal(t, "query_log", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Zero(t, requests.Load())
}

// TestClientQueryLogMutations verifies the pinned clear and configuration
// update request and response contracts.
func TestClientQueryLogMutations(t *testing.T) {
	t.Parallel()

	t.Run("clear", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "/api/control/querylog_clear", r.URL.Path)
			assert.Zero(t, r.ContentLength)
			assert.Empty(t, r.Header.Get("Content-Type"))
			w.Header().Set("Content-Type", "text/plain")

			_, err := w.Write([]byte("ignored"))
			assert.NoError(t, err)
		}))
		client := newQueryLogTestClient(t, server, 7)

		require.NoError(t, client.QueryLogClear(t.Context()))
	})

	t.Run("put config", func(t *testing.T) {
		t.Parallel()

		server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPut, r.Method)
			assert.Equal(t, "/api/control/querylog/config/update", r.URL.Path)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))

			body, err := io.ReadAll(r.Body)
			assert.NoError(t, err)
			assert.JSONEq(t, `{
				"enabled":false,
				"interval":0,
				"anonymize_client_ip":false,
				"ignored":[],
				"ignored_enabled":false
			}`, string(body))
			w.WriteHeader(http.StatusOK)
		}))
		client := newQueryLogTestClient(t, server, 1)

		err := client.PutQueryLogConfig(t.Context(), QueryLogConfig{
			Enabled:           false,
			Interval:          0,
			AnonymizeClientIP: false,
			Ignored:           []string{},
			IgnoredEnabled:    new(false),
		})

		require.NoError(t, err)
	})
}

// TestClientPutQueryLogConfigRequiresIgnoredArray verifies that a configuration
// update without the required ignored array is rejected before any request.
func TestClientPutQueryLogConfigRequiresIgnoredArray(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newQueryLogTestClient(t, server, queryLogResponseLimit)

	err := client.PutQueryLogConfig(t.Context(), QueryLogConfig{})

	clientErr := requireQueryLogError(t, err, ErrorKindRequest)
	assert.Equal(t, "put_query_log_config", clientErr.Operation)
	assert.Equal(t, http.MethodPut, clientErr.Method)
	assert.Zero(t, requests.Load())
}

// TestClientQueryLogStatusErrors verifies that every query-log operation
// reports a non-success HTTP status as a structured status failure.
func TestClientQueryLogStatusErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		operation string
		method    string
		call      func(context.Context, *Client) error
	}{
		{
			name: "query log", operation: "query_log", method: http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryLog(ctx, &QueryLogRequest{})

				return err
			},
		},
		{
			name: "clear", operation: "query_log_clear", method: http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				return client.QueryLogClear(ctx)
			},
		},
		{
			name: "get config", operation: "get_query_log_config", method: http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetQueryLogConfig(ctx)

				return err
			},
		},
		{
			name: "put config", operation: "put_query_log_config", method: http.MethodPut,
			call: func(ctx context.Context, client *Client) error {
				return client.PutQueryLogConfig(ctx, QueryLogConfig{Ignored: []string{}})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogResponseServer(t, "text/plain", "query log failure", http.StatusTeapot)
			client := newQueryLogTestClient(t, server, queryLogResponseLimit)

			err := test.call(t.Context(), client)

			clientErr := requireQueryLogError(t, err, ErrorKindStatus)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusTeapot, clientErr.StatusCode)
			assert.Equal(t, "418 I'm a teapot", clientErr.Status)
			assert.Equal(t, "text/plain", clientErr.ContentType)
			assert.Equal(t, "query log failure", string(clientErr.Body))
		})
	}
}

// TestClientQueryLogRejectsInvalidJSON verifies that malformed, null, and
// incomplete query-log response bodies are rejected as JSON failures.
func TestClientQueryLogRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		operation string
		call      func(context.Context, *Client) error
	}{
		{
			name: "malformed", body: `{"data":`, operation: "query_log",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryLog(ctx, &QueryLogRequest{})

				return err
			},
		},
		{
			name: "null object", body: `null`, operation: "query_log",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryLog(ctx, &QueryLogRequest{})

				return err
			},
		},
		{
			name: "invalid reason", body: `{"data":[{"reason":"FutureReason"}]}`, operation: "query_log",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryLog(ctx, &QueryLogRequest{})

				return err
			},
		},
		{
			name:      "incomplete client info",
			body:      `{"data":[{"client_info":{"disallowed":false}}]}`,
			operation: "query_log",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryLog(ctx, &QueryLogRequest{})

				return err
			},
		},
		{
			name: "missing config field", operation: "get_query_log_config",
			body: `{"enabled":true,"interval":1,"anonymize_client_ip":true}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetQueryLogConfig(ctx)

				return err
			},
		},
		{
			name: "null config field", operation: "get_query_log_config",
			body: `{"enabled":true,"interval":1,"anonymize_client_ip":true,"ignored":null}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetQueryLogConfig(ctx)

				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogResponseServer(t, "application/json", test.body, http.StatusOK)
			client := newQueryLogTestClient(t, server, queryLogResponseLimit)

			err := test.call(t.Context(), client)

			clientErr := requireQueryLogError(t, err, ErrorKindJSON)
			assert.Equal(t, test.operation, clientErr.Operation)
		})
	}
}

// TestClientQueryLogEnforcesResponseLimit verifies that every query-log
// operation rejects a response body exceeding the configured limit.
func TestClientQueryLogEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		body      string
		mediaType string
		limit     int64
		operation string
		method    string
		call      func(context.Context, *Client) error
	}{
		{
			name: "JSON response", body: queryLogResponseJSON, mediaType: "application/json",
			limit: int64(len(queryLogResponseJSON)) - 1, operation: "query_log", method: http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.QueryLog(ctx, &QueryLogRequest{})

				return err
			},
		},
		{
			name: "clear response", body: "overflow", mediaType: "text/plain",
			limit: 3, operation: "query_log_clear", method: http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				return client.QueryLogClear(ctx)
			},
		},
		{
			name: "put response", body: "overflow", mediaType: "text/plain",
			limit: 3, operation: "put_query_log_config", method: http.MethodPut,
			call: func(ctx context.Context, client *Client) error {
				return client.PutQueryLogConfig(ctx, QueryLogConfig{Ignored: []string{}})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newQueryLogResponseServer(t, test.mediaType, test.body, http.StatusOK)
			client := newQueryLogTestClient(t, server, test.limit)

			err := test.call(t.Context(), client)

			clientErr := requireQueryLogError(t, err, ErrorKindResponseTooLarge)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.limit, clientErr.Limit)
		})
	}
}

// TestClientQueryLogHonorsCancellation verifies that a canceled context
// prevents the query-log request from reaching the server.
func TestClientQueryLogHonorsCancellation(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newQueryLogTestClient(t, server, queryLogResponseLimit)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err := client.QueryLog(ctx, &QueryLogRequest{})

	clientErr := requireQueryLogError(t, err, ErrorKindRequest)
	assert.Equal(t, "query_log", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, requests.Load())
}

// TestClientQueryLogHonorsRequestTimeout verifies that the configured request
// timeout bounds a stalled query-log response.
func TestClientQueryLogHonorsRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	httpClient := server.Client()
	client, err := NewClient(
		queryLogBaseURL,
		WithHTTPClient(httpClient),
		WithRequestTimeout(20*time.Millisecond),
		WithMaxResponseBodySize(queryLogResponseLimit),
	)
	require.NoError(t, err)

	err = client.QueryLogClear(t.Context())

	clientErr := requireQueryLogError(t, err, ErrorKindRequest)
	assert.Equal(t, "query_log_clear", clientErr.Operation)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// newQueryLogResponseServer creates a server returning one fixed query-log
// response.
//
// Parameters:
//   - t: The test context owning the server.
//   - mediaType: The response media type, or an empty string to omit it.
//   - body: The response body written for every request.
//   - statusCode: The HTTP status code written before the body.
//
// Returns:
//   - server: The in-memory query-log server.
func newQueryLogResponseServer(
	t *testing.T,
	mediaType string,
	body string,
	statusCode int,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if mediaType != "" {
			w.Header().Set("Content-Type", mediaType)
		}

		w.WriteHeader(statusCode)

		_, err := w.Write([]byte(body))
		assert.NoError(t, err)
	}))
}

// newQueryLogTestClient creates a client routed to one in-memory query-log
// server.
//
// Parameters:
//   - t: The test context receiving configuration failures.
//   - server: The in-memory query-log server.
//   - limit: The configured maximum response body size.
//
// Returns:
//   - client: The query-log client under test.
func newQueryLogTestClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *Client {
	t.Helper()

	client, err := NewClient(
		queryLogBaseURL,
		WithHTTPClient(server.Client()),
		WithBasicAuth(queryLogUsername, queryLogPassword),
		WithUserAgent(queryLogUserAgent),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// requireQueryLogError extracts a structured query-log client error and
// verifies its error kind.
//
// Parameters:
//   - t: The test context receiving assertion failures.
//   - err: The error to inspect.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireQueryLogError(t *testing.T, err error, kind ErrorKind) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}

// TestQueryLogJSONRoundTrip verifies that a fully present query-log
// configuration survives JSON encoding and decoding unchanged.
func TestQueryLogJSONRoundTrip(t *testing.T) {
	t.Parallel()

	config := QueryLogConfig{
		Enabled:           true,
		Interval:          7,
		AnonymizeClientIP: true,
		Ignored:           []string{"localhost"},
		IgnoredEnabled:    new(true),
	}
	encoded, err := json.Marshal(config)
	require.NoError(t, err)

	var decoded QueryLogConfig

	require.NoError(t, json.Unmarshal(encoded, &decoded))
	assert.Equal(t, config, decoded)
}
