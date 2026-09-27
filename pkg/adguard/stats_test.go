// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statsRequestContract describes one statistics HTTP request contract.
type statsRequestContract struct {
	// name is the subtest name.
	name string
	// method is the expected HTTP method.
	method string
	// path is the expected API path.
	path string
	// rawQuery is the expected encoded query string.
	rawQuery string
	// requestBody is the expected JSON body, or an empty string for no body.
	requestBody string
	// responseType is the response Content-Type.
	responseType string
	// responseBody is the response body returned by the server.
	responseBody string
	// call invokes the statistics operation under test.
	call func(context.Context, *Client) error
}

const (
	// Statistics JSON media type.
	statsJSONMediaType = "application/json"
	// Statistics text media type.
	statsTextMediaType = "text/plain"
	// Statistics endpoint path.
	statsEndpointPath = "/api/control/stats"
	// A top-level JSON null.
	statsNullJSON = "null"
	// Statistics JSON contains every field in the schema.
	statsValidResponseJSON = `{
		"time_units":"hours",
		"num_dns_queries":100,
		"num_blocked_filtering":40,
		"num_replaced_safebrowsing":10,
		"num_replaced_safesearch":5,
		"num_replaced_parental":3,
		"avg_processing_time":0.25,
		"top_queried_domains":[{"example.org":10.5},null],
		"top_clients":[{"192.0.2.1":20.5}],
		"top_blocked_domains":[{"ads.example":5.5}],
		"top_upstreams_responses":[{"1.1.1.1":30.5}],
		"top_upstreams_avg_time":[{"1.1.1.1":0.01}],
		"dns_queries":[100,200],
		"blocked_filtering":[40,50],
		"replaced_safebrowsing":[10,15],
		"replaced_parental":[3,4]
	}`
	// Statistics configuration JSON contains all schema fields.
	statsValidConfigJSON = `{
		"enabled":true,
		"interval":86400000,
		"ignored":["localhost","router.local"],
		"ignored_enabled":false
	}`
	// Statistics JSON contains an explicit null for every optional field.
	statsNullFieldsJSON = `{
		"time_units":null,
		"num_dns_queries":null,
		"num_blocked_filtering":null,
		"num_replaced_safebrowsing":null,
		"num_replaced_safesearch":null,
		"num_replaced_parental":null,
		"avg_processing_time":null,
		"top_queried_domains":null,
		"top_clients":null,
		"top_blocked_domains":null,
		"top_upstreams_responses":null,
		"top_upstreams_avg_time":null,
		"dns_queries":null,
		"blocked_filtering":null,
		"replaced_safebrowsing":null,
		"replaced_parental":null
	}`
	// Statistics JSON contains explicit zero and empty values.
	statsExplicitZeroJSON = `{
		"time_units":"hours",
		"num_dns_queries":0,
		"num_blocked_filtering":0,
		"num_replaced_safebrowsing":0,
		"num_replaced_safesearch":0,
		"num_replaced_parental":0,
		"avg_processing_time":0,
		"top_queried_domains":[],
		"top_clients":[],
		"top_blocked_domains":[],
		"top_upstreams_responses":[],
		"top_upstreams_avg_time":[],
		"dns_queries":[],
		"blocked_filtering":[],
		"replaced_safebrowsing":[],
		"replaced_parental":[]
	}`
)

// TestClientStatsRequestContract verifies every statistics HTTP contract.
func TestClientStatsRequestContract(t *testing.T) {
	t.Parallel()

	for _, test := range statsRequestContracts() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testStatsRequest(t, test)
		})
	}
}

// TestClientStatsResponseModel verifies the complete typed statistics response.
func TestClientStatsResponseModel(t *testing.T) {
	t.Parallel()

	client := newStatsJSONClient(t, statsValidResponseJSON)

	statistics, err := client.Stats(t.Context(), nil)

	require.NoError(t, err)
	assert.Equal(t, &Stats{
		TimeUnits:               new(StatsTimeUnitHours),
		NumDNSQueries:           new(int64(100)),
		NumBlockedFiltering:     new(int64(40)),
		NumReplacedSafebrowsing: new(int64(10)),
		NumReplacedSafesearch:   new(int64(5)),
		NumReplacedParental:     new(int64(3)),
		AvgProcessingTime:       new(0.25),
		TopQueriedDomains:       &[]StatsEntry{{"example.org": 10.5}, nil},
		TopClients:              &[]StatsEntry{{"192.0.2.1": 20.5}},
		TopBlockedDomains:       &[]StatsEntry{{"ads.example": 5.5}},
		TopUpstreamsResponses:   &[]StatsEntry{{"1.1.1.1": 30.5}},
		TopUpstreamsAvgTime:     &[]StatsEntry{{"1.1.1.1": 0.01}},
		DNSQueries:              &[]int64{100, 200},
		BlockedFiltering:        &[]int64{40, 50},
		ReplacedSafebrowsing:    &[]int64{10, 15},
		ReplacedParental:        &[]int64{3, 4},
	}, statistics)
}

// TestClientStatsOptionalPresence verifies absent, null, and explicit zero values.
func TestClientStatsOptionalPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *Stats
	}{
		{name: "absent", body: `{}`, want: &Stats{}},
		{name: "null", body: statsNullFieldsJSON, want: &Stats{}},
		{
			name: "explicit zero",
			body: statsExplicitZeroJSON,
			want: &Stats{
				TimeUnits:               new(StatsTimeUnitHours),
				NumDNSQueries:           new(int64(0)),
				NumBlockedFiltering:     new(int64(0)),
				NumReplacedSafebrowsing: new(int64(0)),
				NumReplacedSafesearch:   new(int64(0)),
				NumReplacedParental:     new(int64(0)),
				AvgProcessingTime:       new(float64(0)),
				TopQueriedDomains:       &[]StatsEntry{},
				TopClients:              &[]StatsEntry{},
				TopBlockedDomains:       &[]StatsEntry{},
				TopUpstreamsResponses:   &[]StatsEntry{},
				TopUpstreamsAvgTime:     &[]StatsEntry{},
				DNSQueries:              &[]int64{},
				BlockedFiltering:        &[]int64{},
				ReplacedSafebrowsing:    &[]int64{},
				ReplacedParental:        &[]int64{},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newStatsJSONClient(t, test.body)

			statistics, err := client.Stats(t.Context(), nil)

			require.NoError(t, err)
			assert.Equal(t, test.want, statistics)
		})
	}
}

// TestClientGetStatsConfig verifies required fields and explicit optional false.
func TestClientGetStatsConfig(t *testing.T) {
	t.Parallel()

	client := newStatsJSONClient(t, statsValidConfigJSON)

	config, err := client.GetStatsConfig(t.Context())

	require.NoError(t, err)
	assert.Equal(t, &StatsConfig{
		Enabled:        true,
		Interval:       86_400_000,
		Ignored:        []string{"localhost", "router.local"},
		IgnoredEnabled: new(false),
	}, config)
}

// TestClientStatsConfigOptionalPresence verifies ignored_enabled presence semantics.
func TestClientStatsConfigOptionalPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want *bool
	}{
		{
			name: "absent",
			body: `{"enabled":true,"interval":0,"ignored":[]}`,
		},
		{
			name: "null",
			body: `{"enabled":true,"interval":0,"ignored":[],"ignored_enabled":null}`,
		},
		{
			name: "false",
			body: `{"enabled":true,"interval":0,"ignored":[],"ignored_enabled":false}`,
			want: new(false),
		},
		{
			name: "true",
			body: `{"enabled":true,"interval":0,"ignored":[],"ignored_enabled":true}`,
			want: new(true),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := newStatsJSONClient(t, test.body)

			config, err := client.GetStatsConfig(t.Context())

			require.NoError(t, err)
			assert.Equal(t, test.want, config.IgnoredEnabled)
		})
	}
}

// TestClientPutStatsConfigRequestPresence verifies required and optional body fields.
func TestClientPutStatsConfigRequestPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		ignoredState *bool
		wantBody     string
	}{
		{
			name:     "optional absent",
			wantBody: `{"enabled":false,"interval":0,"ignored":[]}`,
		},
		{
			name:         "optional false",
			ignoredState: new(false),
			wantBody:     `{"enabled":false,"interval":0,"ignored":[],"ignored_enabled":false}`,
		},
		{
			name:         "optional true",
			ignoredState: new(true),
			wantBody:     `{"enabled":false,"interval":0,"ignored":[],"ignored_enabled":true}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testPutStatsConfigRequest(t, test.wantBody, test.ignoredState)
		})
	}
}

// testPutStatsConfigRequest verifies one configuration update request body.
func testPutStatsConfigRequest(t *testing.T, wantBody string, ignoredState *bool) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		if err != nil {
			return
		}

		assert.JSONEq(t, wantBody, string(body))
		w.WriteHeader(http.StatusOK)
	}))
	client := newStatsTestClient(t, server, 4096)

	err := client.PutStatsConfig(t.Context(), StatsConfig{
		Enabled:        false,
		Interval:       0,
		Ignored:        []string{},
		IgnoredEnabled: ignoredState,
	})

	require.NoError(t, err)
}

// TestClientPutStatsConfigRequiresIgnored verifies local required-list validation.
func TestClientPutStatsConfigRequiresIgnored(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newStatsTestClient(t, server, 4096)

	err := client.PutStatsConfig(t.Context(), StatsConfig{
		Enabled:        false,
		Interval:       0,
		Ignored:        nil,
		IgnoredEnabled: nil,
	})

	clientErr := requireStatsError(t, err, ErrorKindRequest)
	assert.Equal(t, "put_stats_config", clientErr.Operation)
	assert.Equal(t, http.MethodPut, clientErr.Method)
	assert.Zero(t, requests.Load())
}

// TestClientStatsRejectsInvalidJSONResponses verifies strict JSON contract validation.
func TestClientStatsRejectsInvalidJSONResponses(t *testing.T) {
	t.Parallel()

	for _, test := range statsJSONFailureCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", test.contentType)
				writeStatsResponse(t, w, test.body)
			}))
			client := newStatsTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireStatsError(t, err, ErrorKindJSON)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestClientStatsRejectsWrongContentType verifies JSON response media types.
func TestClientStatsRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		body   string
		call   func(context.Context, *Client) error
	}{
		{
			name:   "statistics",
			method: http.MethodGet,
			body:   `{}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
		},
		{
			name:   "configuration",
			method: http.MethodGet,
			body:   statsValidConfigJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", statsTextMediaType)
				writeStatsResponse(t, w, test.body)
			}))
			client := newStatsTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireStatsError(t, err, ErrorKindContentType)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, statsTextMediaType, clientErr.ContentType)
		})
	}
}

// TestClientStatsRejectsNonSuccessResponses verifies status error metadata.
func TestClientStatsRejectsNonSuccessResponses(t *testing.T) {
	t.Parallel()

	for _, test := range statsOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", statsTextMediaType)
				w.WriteHeader(http.StatusTeapot)
				writeStatsResponse(t, w, "statistics failure")
			}))
			client := newStatsTestClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireStatsError(t, err, ErrorKindStatus)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusTeapot, clientErr.StatusCode)
			assert.Equal(t, "418 I'm a teapot", clientErr.Status)
			assert.Equal(t, statsTextMediaType, clientErr.ContentType)
			assert.Equal(t, "statistics failure", string(clientErr.Body))
		})
	}
}

// TestClientStatsEnforcesResponseLimit verifies bounded JSON and empty responses.
func TestClientStatsEnforcesResponseLimit(t *testing.T) {
	t.Parallel()

	contentTypes := []string{
		statsJSONMediaType,
		statsTextMediaType,
		statsJSONMediaType,
		statsTextMediaType,
	}
	bodies := []string{
		statsValidResponseJSON,
		"unexpected",
		statsValidConfigJSON,
		"unexpected",
	}

	for index, test := range statsOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", contentTypes[index])
				writeStatsResponse(t, w, bodies[index])
			}))
			client := newStatsTestClient(t, server, 4)

			err := test.call(t.Context(), client)

			clientErr := requireStatsError(t, err, ErrorKindResponseTooLarge)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, int64(4), clientErr.Limit)
		})
	}
}

// TestClientStatsHonorsCancellation verifies context cancellation for every method.
func TestClientStatsHonorsCancellation(t *testing.T) {
	t.Parallel()

	for _, test := range statsOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			client := newStatsTestClient(t, server, 4096)
			ctx, cancel := context.WithCancel(t.Context())
			cancel()

			err := test.call(ctx, client)

			clientErr := requireStatsError(t, err, ErrorKindRequest)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.ErrorIs(t, err, context.Canceled)
		})
	}
}

// TestClientStatsHonorsRequestTimeout verifies the custom query request deadline.
func TestClientStatsHonorsRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client := newStatsTestClient(
		t,
		server,
		4096,
		WithRequestTimeout(20*time.Millisecond),
	)

	_, err := client.Stats(t.Context(), &StatsRequest{Recent: new(int64(3_600_000))})

	clientErr := requireStatsError(t, err, ErrorKindRequest)
	assert.Equal(t, "stats", clientErr.Operation)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// statsRequestContracts returns every statistics request contract.
func statsRequestContracts() []statsRequestContract {
	return append(statsReadRequestContracts(), statsWriteRequestContracts()...)
}

// statsReadRequestContracts returns statistics read request contracts.
func statsReadRequestContracts() []statsRequestContract {
	return []statsRequestContract{
		{
			name:         "statistics without request",
			method:       http.MethodGet,
			path:         statsEndpointPath,
			rawQuery:     "",
			requestBody:  "",
			responseType: statsJSONMediaType,
			responseBody: `{}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
		},
		{
			name:         "statistics without recent",
			method:       http.MethodGet,
			path:         statsEndpointPath,
			rawQuery:     "",
			requestBody:  "",
			responseType: statsJSONMediaType,
			responseBody: `{}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, &StatsRequest{Recent: nil})

				return err
			},
		},
		{
			name:         "statistics with recent",
			method:       http.MethodGet,
			path:         statsEndpointPath,
			rawQuery:     "recent=7776000000",
			requestBody:  "",
			responseType: statsJSONMediaType,
			responseBody: `{}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, &StatsRequest{Recent: new(int64(7_776_000_000))})

				return err
			},
		},
		{
			name:         "statistics with explicit zero recent",
			method:       http.MethodGet,
			path:         statsEndpointPath,
			rawQuery:     "recent=0",
			requestBody:  "",
			responseType: statsJSONMediaType,
			responseBody: `{}`,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, &StatsRequest{Recent: new(int64(0))})

				return err
			},
		},
	}
}

// statsWriteRequestContracts returns reset and configuration request contracts.
func statsWriteRequestContracts() []statsRequestContract {
	return []statsRequestContract{
		{
			name:         "reset",
			method:       http.MethodPost,
			path:         "/api/control/stats_reset",
			rawQuery:     "",
			requestBody:  "",
			responseType: statsTextMediaType,
			responseBody: "ignored successful body",
			call: func(ctx context.Context, client *Client) error {
				return client.StatsReset(ctx)
			},
		},
		{
			name:         "get configuration",
			method:       http.MethodGet,
			path:         "/api/control/stats/config",
			rawQuery:     "",
			requestBody:  "",
			responseType: statsJSONMediaType,
			responseBody: statsValidConfigJSON,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
		{
			name:         "put configuration",
			method:       http.MethodPut,
			path:         "/api/control/stats/config/update",
			rawQuery:     "",
			requestBody:  `{"enabled":false,"interval":0,"ignored":[],"ignored_enabled":false}`,
			responseType: statsTextMediaType,
			responseBody: "ignored successful body",
			call: func(ctx context.Context, client *Client) error {
				return client.PutStatsConfig(ctx, StatsConfig{
					Enabled:        false,
					Interval:       0,
					Ignored:        []string{},
					IgnoredEnabled: new(false),
				})
			},
		},
	}
}

// statsJSONFailureCases returns invalid statistics JSON success responses.
func statsJSONFailureCases() []struct {
	name        string
	contentType string
	body        string
	operation   string
	call        func(context.Context, *Client) error
} {
	oversizedEntries := strings.TrimSuffix(strings.Repeat("{},", 101), ",")

	return append(
		statsInvalidStatsResponseCases(oversizedEntries),
		statsInvalidConfigResponseCases()...,
	)
}

// statsInvalidStatsResponseCases returns invalid statistics response cases.
func statsInvalidStatsResponseCases(oversizedEntries string) []struct {
	name        string
	contentType string
	body        string
	operation   string
	call        func(context.Context, *Client) error
} {
	return []struct {
		name        string
		contentType string
		body        string
		operation   string
		call        func(context.Context, *Client) error
	}{
		{
			name:        "malformed statistics",
			contentType: statsJSONMediaType,
			body:        `{"time_units":`,
			operation:   "stats",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
		},
		{
			name:        "null statistics",
			contentType: statsJSONMediaType,
			body:        statsNullJSON,
			operation:   "stats",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
		},
		{
			name:        "invalid time unit",
			contentType: statsJSONMediaType,
			body:        `{"time_units":"minutes"}`,
			operation:   "stats",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
		},
		{
			name:        "too many upstream responses",
			contentType: statsJSONMediaType,
			body:        `{"top_upstreams_responses":[` + oversizedEntries + `]}`,
			operation:   "stats",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
		},
	}
}

// statsInvalidConfigResponseCases returns invalid configuration response cases.
func statsInvalidConfigResponseCases() []struct {
	name        string
	contentType string
	body        string
	operation   string
	call        func(context.Context, *Client) error
} {
	return []struct {
		name        string
		contentType string
		body        string
		operation   string
		call        func(context.Context, *Client) error
	}{
		{
			name:        "malformed configuration",
			contentType: statsJSONMediaType,
			body:        `{"enabled":`,
			operation:   "get_stats_config",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
		{
			name:        "null configuration",
			contentType: statsJSONMediaType,
			body:        statsNullJSON,
			operation:   "get_stats_config",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
		{
			name:        "missing enabled",
			contentType: statsJSONMediaType,
			body:        `{"interval":0,"ignored":[]}`,
			operation:   "get_stats_config",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
		{
			name:        "null interval",
			contentType: statsJSONMediaType,
			body:        `{"enabled":true,"interval":null,"ignored":[]}`,
			operation:   "get_stats_config",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
		{
			name:        "missing ignored",
			contentType: statsJSONMediaType,
			body:        `{"enabled":true,"interval":0}`,
			operation:   "get_stats_config",
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
	}
}

// statsOperationCases returns all statistics operations for transport tests.
func statsOperationCases() []struct {
	name      string
	operation string
	method    string
	call      func(context.Context, *Client) error
} {
	return []struct {
		name      string
		operation string
		method    string
		call      func(context.Context, *Client) error
	}{
		{
			name:      "statistics",
			operation: "stats",
			method:    http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.Stats(ctx, &StatsRequest{Recent: new(int64(0))})

				return err
			},
		},
		{
			name:      "reset",
			operation: "stats_reset",
			method:    http.MethodPost,
			call: func(ctx context.Context, client *Client) error {
				return client.StatsReset(ctx)
			},
		},
		{
			name:      "get configuration",
			operation: "get_stats_config",
			method:    http.MethodGet,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
		},
		{
			name:      "put configuration",
			operation: "put_stats_config",
			method:    http.MethodPut,
			call: func(ctx context.Context, client *Client) error {
				return client.PutStatsConfig(ctx, StatsConfig{
					Enabled:        false,
					Interval:       0,
					Ignored:        []string{},
					IgnoredEnabled: nil,
				})
			},
		},
	}
}

// testStatsRequest verifies one statistics request contract.
func testStatsRequest(t *testing.T, test statsRequestContract) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "stats-user", username)
		assert.Equal(t, "stats-password", password)
		assert.Equal(t, test.method, r.Method)
		assert.Equal(t, test.path, r.URL.Path)
		assert.Equal(t, test.rawQuery, r.URL.RawQuery)
		assert.Equal(t, []string{statsJSONMediaType}, r.Header.Values("Accept"))
		assert.Equal(t, "adguard-stats-test/1.0", r.Header.Get("User-Agent"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		if err != nil {
			return
		}

		if test.requestBody == "" {
			assert.Empty(t, body)
			assert.Zero(t, r.ContentLength)
			assert.Empty(t, r.Header.Get("Content-Type"))
		} else {
			assert.JSONEq(t, test.requestBody, string(body))
			assert.Positive(t, r.ContentLength)
			assert.Equal(t, []string{statsJSONMediaType}, r.Header.Values("Content-Type"))
		}

		w.Header().Set("Content-Type", test.responseType)
		writeStatsResponse(t, w, test.responseBody)
	}))
	client := newStatsTestClient(t, server, 4096)

	err := test.call(t.Context(), client)

	require.NoError(t, err)
}

// newStatsJSONClient creates a statistics client returning one JSON response.
func newStatsJSONClient(t *testing.T, responseBody string) *Client {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", statsJSONMediaType)
		writeStatsResponse(t, w, responseBody)
	}))

	return newStatsTestClient(t, server, 4096)
}

// newStatsTestClient creates a concrete statistics client for an HTTP test server.
func newStatsTestClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
	options ...Option,
) *Client {
	t.Helper()

	clientOptions := make([]Option, 0, len(options)+4)

	clientOptions = append(
		clientOptions,
		WithHTTPClient(server.Client()),
		WithBasicAuth("stats-user", "stats-password"),
		WithUserAgent("adguard-stats-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	clientOptions = append(clientOptions, options...)

	serverURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	serverURL.Host = net.JoinHostPort("localhost", serverURL.Port())
	serverURL.Path = "/api/"

	client, err := NewClient(serverURL.String(), clientOptions...)
	require.NoError(t, err)

	return client
}

// requireStatsError returns a typed client error of the expected kind.
func requireStatsError(
	t *testing.T,
	err error,
	wantKind ErrorKind,
) *Error {
	t.Helper()

	require.Error(t, err)

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	require.Equal(t, wantKind, clientErr.Kind)

	return clientErr
}

// writeStatsResponse writes one complete HTTP test response body.
func writeStatsResponse(t *testing.T, writer http.ResponseWriter, body string) {
	t.Helper()

	_, err := writer.Write([]byte(body))
	assert.NoError(t, err)
}
