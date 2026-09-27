// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// statsIntegrationCall invokes one statistics operation.
type statsIntegrationCall func(context.Context, *adguard.Client) error

// statsIntegrationRequestContract describes one successful HTTP contract.
type statsIntegrationRequestContract struct {
	call                statsIntegrationCall
	method              string
	name                string
	path                string
	query               string
	requestBody         string
	responseBody        string
	responseContentType string
	status              int
}

// statsIntegrationRequestCapture contains the metadata from one HTTP request.
type statsIntegrationRequestCapture struct {
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

// statsIntegrationOperation describes one operation for transport-level tests.
type statsIntegrationOperation struct {
	call      statsIntegrationCall
	method    string
	name      string
	operation string
	path      string
	query     string
}

// statsIntegrationResponseErrorCase describes one invalid JSON response.
type statsIntegrationResponseErrorCase struct {
	body            string
	call            statsIntegrationCall
	contentType     string
	kind            adguard.ErrorKind
	method          string
	name            string
	operation       string
	wantContentType string
}

const (
	// The loopback URL is routed by the in-memory test transport.
	statsIntegrationBaseURL = "http://127.0.0.1"
	// The expected Basic Auth username follows.
	statsIntegrationUsername = "stats-integration-user"
	// The expected Basic Auth password follows.
	statsIntegrationPassword = "stats-integration-password"
	// The expected client User-Agent follows.
	statsIntegrationUserAgent = "stats-integration-client/1.0"
	// The request and response JSON media type follows.
	statsIntegrationJSONMediaType = "application/json"
	// A valid parameterized JSON response type follows.
	statsIntegrationResponseMediaType = "application/json; charset=utf-8"
	// The structured error response media type follows.
	statsIntegrationProblemMediaType = "application/problem+json; charset=utf-8"
	// The structured non-success response body follows.
	statsIntegrationErrorBody = `{"message":"statistics request rejected"}`
	// A complete statistics configuration response follows.
	statsIntegrationConfigResponse = `{
		"enabled":true,
		"interval":86400000,
		"ignored":["localhost","router.local"],
		"ignored_enabled":false
	}`
	// A complete statistics response follows.
	statsIntegrationStatsResponse = `{
		"time_units":"days",
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
)

// TestStatsIntegrationRequestContracts verifies every statistics request contract.
func TestStatsIntegrationRequestContracts(t *testing.T) {
	t.Parallel()

	contracts := statsIntegrationRequestContracts()
	for index := range contracts {
		test := &contracts[index]

		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runStatsIntegrationRequestContract(t, test)
		})
	}
}

// TestStatsIntegrationDecodesJSONResponses verifies complete statistics response models.
func TestStatsIntegrationDecodesJSONResponses(t *testing.T) {
	t.Parallel()

	t.Run("statistics", testStatsIntegrationStatisticsResponse)
	t.Run("configuration", testStatsIntegrationConfigResponse)
}

// TestStatsIntegrationPreservesOptionalFields verifies omitted, null, and explicit values.
func TestStatsIntegrationPreservesOptionalFields(t *testing.T) {
	t.Parallel()

	t.Run("statistics", testStatsIntegrationOptionalStatisticsFields)
	t.Run("configuration", testStatsIntegrationOptionalConfigField)
}

// TestStatsIntegrationRejectsMalformedInput verifies local request validation.
func TestStatsIntegrationRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	client := newStatsIntegrationClient(t, server, 4096)

	err := client.PutStatsConfig(t.Context(), adguard.StatsConfig{})

	clientErr := requireStatsIntegrationError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, "put_stats_config", clientErr.Operation)
	assert.Equal(t, http.MethodPut, clientErr.Method)
	require.Error(t, clientErr.Err)
	assert.Zero(t, requests.Load())
}

// TestStatsIntegrationReturnsStructuredStatusErrors verifies HTTP error metadata.
func TestStatsIntegrationReturnsStructuredStatusErrors(t *testing.T) {
	t.Parallel()

	for _, operation := range statsIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			runStatsIntegrationStatusError(t, operation)
		})
	}
}

// TestStatsIntegrationReturnsStructuredResponseErrors verifies JSON contract errors.
func TestStatsIntegrationReturnsStructuredResponseErrors(t *testing.T) {
	t.Parallel()

	for _, test := range statsIntegrationResponseErrorCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newStatsIntegrationResponseServer(t, test.contentType, test.body)
			client := newStatsIntegrationClient(t, server, 4096)

			err := test.call(t.Context(), client)

			clientErr := requireStatsIntegrationError(t, err, test.kind)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.wantContentType, clientErr.ContentType)
			require.Error(t, clientErr.Err)
		})
	}
}

// TestStatsIntegrationEnforcesResponseLimits verifies bounded responses for every operation.
func TestStatsIntegrationEnforcesResponseLimits(t *testing.T) {
	t.Parallel()

	const limit = int64(3)

	for _, operation := range statsIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			server := newStatsIntegrationResponseServer(t, statsIntegrationJSONMediaType, "overflow")
			client := newStatsIntegrationClient(t, server, limit)

			err := operation.call(t.Context(), client)

			clientErr := requireStatsIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
			//nolint:testifylint // encoded-compare: Exact HTTP media-type equality is required.
			assert.Equal(t, statsIntegrationJSONMediaType, clientErr.ContentType)
			assert.Equal(t, limit, clientErr.Limit)
		})
	}
}

// TestStatsIntegrationEnforcesUpstreamEntryLimit verifies the 100-entry schema boundary.
func TestStatsIntegrationEnforcesUpstreamEntryLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		count   int
		field   string
		name    string
		wantErr bool
	}{
		{name: "responses at limit", count: 100, field: "top_upstreams_responses"},
		{name: "responses over limit", count: 101, field: "top_upstreams_responses", wantErr: true},
		{name: "average times at limit", count: 100, field: "top_upstreams_avg_time"},
		{name: "average times over limit", count: 101, field: "top_upstreams_avg_time", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			entries := strings.TrimSuffix(strings.Repeat("{},", test.count), ",")
			body := `{"time_units":"hours","` + test.field + `":[` + entries + `]}`
			server := newStatsIntegrationResponseServer(t, statsIntegrationJSONMediaType, body)
			client := newStatsIntegrationClient(t, server, 4096)

			statistics, err := client.Stats(t.Context(), nil)

			if test.wantErr {
				assert.Nil(t, statistics)

				clientErr := requireStatsIntegrationError(t, err, adguard.ErrorKindJSON)
				assert.Equal(t, "stats", clientErr.Operation)
				assert.Equal(t, http.MethodGet, clientErr.Method)
				require.Error(t, clientErr.Err)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, statistics)

			assertStatsIntegrationUpstreamEntries(t, statistics, test.field, test.count)
		})
	}
}

// assertStatsIntegrationUpstreamEntries verifies one decoded upstream collection.
//
// Parameters:
//   - t: The test context receiving assertion failures.
//   - statistics: The decoded statistics response.
//   - field: The bounded upstream collection field name.
//   - count: The number of expected upstream entries.
func assertStatsIntegrationUpstreamEntries(
	t *testing.T,
	statistics *adguard.Stats,
	field string,
	count int,
) {
	t.Helper()

	if field == "top_upstreams_responses" {
		require.NotNil(t, statistics.TopUpstreamsResponses)
		assert.Len(t, *statistics.TopUpstreamsResponses, count)

		return
	}

	require.NotNil(t, statistics.TopUpstreamsAvgTime)
	assert.Len(t, *statistics.TopUpstreamsAvgTime, count)
}

// TestStatsIntegrationHonorsCancellation verifies cancellation for every operation.
func TestStatsIntegrationHonorsCancellation(t *testing.T) {
	t.Parallel()

	for _, operation := range statsIntegrationOperations() {
		t.Run(operation.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				requests.Add(1)
			}))
			client := newStatsIntegrationClient(t, server, 4096)
			ctx, cancel := context.WithCancel(t.Context())

			cancel()

			err := operation.call(ctx, client)

			clientErr := requireStatsIntegrationError(t, err, adguard.ErrorKindRequest)
			assert.Equal(t, operation.operation, clientErr.Operation)
			assert.Equal(t, operation.method, clientErr.Method)
			require.ErrorIs(t, err, context.Canceled)
			assert.Zero(t, requests.Load())
		})
	}
}

// testStatsIntegrationStatisticsResponse verifies complete statistics decoding.
func testStatsIntegrationStatisticsResponse(t *testing.T) {
	t.Helper()
	t.Parallel()

	server := newStatsIntegrationResponseServer(
		t,
		statsIntegrationResponseMediaType,
		statsIntegrationStatsResponse,
	)
	client := newStatsIntegrationClient(t, server, 16<<10)

	statistics, err := client.Stats(t.Context(), nil)

	require.NoError(t, err)
	assert.Equal(t, &adguard.Stats{
		TimeUnits:               new(adguard.StatsTimeUnitDays),
		NumDNSQueries:           new(int64(100)),
		NumBlockedFiltering:     new(int64(40)),
		NumReplacedSafebrowsing: new(int64(10)),
		NumReplacedSafesearch:   new(int64(5)),
		NumReplacedParental:     new(int64(3)),
		AvgProcessingTime:       new(0.25),
		TopQueriedDomains:       &[]adguard.StatsEntry{{"example.org": 10.5}, nil},
		TopClients:              &[]adguard.StatsEntry{{"192.0.2.1": 20.5}},
		TopBlockedDomains:       &[]adguard.StatsEntry{{"ads.example": 5.5}},
		TopUpstreamsResponses:   &[]adguard.StatsEntry{{"1.1.1.1": 30.5}},
		TopUpstreamsAvgTime:     &[]adguard.StatsEntry{{"1.1.1.1": 0.01}},
		DNSQueries:              &[]int64{100, 200},
		BlockedFiltering:        &[]int64{40, 50},
		ReplacedSafebrowsing:    &[]int64{10, 15},
		ReplacedParental:        &[]int64{3, 4},
	}, statistics)
}

// testStatsIntegrationConfigResponse verifies complete configuration decoding.
func testStatsIntegrationConfigResponse(t *testing.T) {
	t.Helper()
	t.Parallel()

	server := newStatsIntegrationResponseServer(
		t,
		statsIntegrationResponseMediaType,
		statsIntegrationConfigResponse,
	)
	client := newStatsIntegrationClient(t, server, 4096)

	config, err := client.GetStatsConfig(t.Context())

	require.NoError(t, err)
	assert.Equal(t, &adguard.StatsConfig{
		Enabled:        true,
		Interval:       86_400_000,
		Ignored:        []string{"localhost", "router.local"},
		IgnoredEnabled: new(false),
	}, config)
}

// testStatsIntegrationOptionalStatisticsFields verifies statistics pointer presence semantics.
func testStatsIntegrationOptionalStatisticsFields(t *testing.T) {
	t.Helper()
	t.Parallel()

	tests := []struct {
		body string
		name string
		want *adguard.Stats
	}{
		{name: "absent", body: `{}`, want: &adguard.Stats{}},
		{
			name: "null",
			body: `{
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
			}`,
			want: &adguard.Stats{},
		},
		{
			name: "explicit zero",
			body: `{
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
			}`,
			want: &adguard.Stats{
				TimeUnits:               new(adguard.StatsTimeUnitHours),
				NumDNSQueries:           new(int64(0)),
				NumBlockedFiltering:     new(int64(0)),
				NumReplacedSafebrowsing: new(int64(0)),
				NumReplacedSafesearch:   new(int64(0)),
				NumReplacedParental:     new(int64(0)),
				AvgProcessingTime:       new(float64(0)),
				TopQueriedDomains:       &[]adguard.StatsEntry{},
				TopClients:              &[]adguard.StatsEntry{},
				TopBlockedDomains:       &[]adguard.StatsEntry{},
				TopUpstreamsResponses:   &[]adguard.StatsEntry{},
				TopUpstreamsAvgTime:     &[]adguard.StatsEntry{},
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

			server := newStatsIntegrationResponseServer(t, statsIntegrationJSONMediaType, test.body)
			client := newStatsIntegrationClient(t, server, 4096)

			statistics, err := client.Stats(t.Context(), nil)

			require.NoError(t, err)
			assert.Equal(t, test.want, statistics)
		})
	}
}

// testStatsIntegrationOptionalConfigField verifies optional boolean presence semantics.
func testStatsIntegrationOptionalConfigField(t *testing.T) {
	t.Helper()
	t.Parallel()

	tests := []struct {
		body string
		name string
		want *bool
	}{
		{name: "absent", body: `{"enabled":true,"interval":0,"ignored":[]}`},
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

			server := newStatsIntegrationResponseServer(t, statsIntegrationJSONMediaType, test.body)
			client := newStatsIntegrationClient(t, server, 4096)

			config, err := client.GetStatsConfig(t.Context())

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

// statsIntegrationRequestContracts returns every successful statistics HTTP contract.
//
// Returns:
//   - The nil, explicit, zero, negative, reset, read, and update cases.
func statsIntegrationRequestContracts() []statsIntegrationRequestContract {
	return []statsIntegrationRequestContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.Stats(ctx, nil)

				return err
			},
			method:              http.MethodGet,
			name:                "statistics without request",
			path:                "/control/stats",
			query:               "",
			requestBody:         "",
			responseBody:        `{}`,
			responseContentType: statsIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.Stats(ctx, &adguard.StatsRequest{Recent: nil})

				return err
			},
			method:              http.MethodGet,
			name:                "statistics without recent",
			path:                "/control/stats",
			query:               "",
			requestBody:         "",
			responseBody:        `{}`,
			responseContentType: statsIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.Stats(ctx, &adguard.StatsRequest{Recent: new(int64(3_600_000))})

				return err
			},
			method:              http.MethodGet,
			name:                "statistics with recent",
			path:                "/control/stats",
			query:               "recent=3600000",
			requestBody:         "",
			responseBody:        `{}`,
			responseContentType: statsIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.Stats(ctx, &adguard.StatsRequest{Recent: new(int64(0))})

				return err
			},
			method:              http.MethodGet,
			name:                "statistics with explicit zero",
			path:                "/control/stats",
			query:               "recent=0",
			requestBody:         "",
			responseBody:        `{}`,
			responseContentType: statsIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.Stats(ctx, &adguard.StatsRequest{Recent: new(int64(-1))})

				return err
			},
			method:              http.MethodGet,
			name:                "statistics with server-validated negative recent",
			path:                "/control/stats",
			query:               "recent=-1",
			requestBody:         "",
			responseBody:        `{}`,
			responseContentType: statsIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.StatsReset(ctx)
			},
			method:              http.MethodPost,
			name:                "reset",
			path:                "/control/stats_reset",
			query:               "",
			requestBody:         "",
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
			method:              http.MethodGet,
			name:                "read configuration",
			path:                "/control/stats/config",
			query:               "",
			requestBody:         "",
			responseBody:        statsIntegrationConfigResponse,
			responseContentType: statsIntegrationResponseMediaType,
			status:              http.StatusOK,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutStatsConfig(ctx, adguard.StatsConfig{
					Enabled:        true,
					Interval:       86_400_000,
					Ignored:        []string{"localhost"},
					IgnoredEnabled: nil,
				})
			},
			method:              http.MethodPut,
			name:                "update configuration without optional field",
			path:                "/control/stats/config/update",
			query:               "",
			requestBody:         `{"enabled":true,"interval":86400000,"ignored":["localhost"]}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutStatsConfig(ctx, adguard.StatsConfig{
					Enabled:        false,
					Interval:       0,
					Ignored:        []string{},
					IgnoredEnabled: new(false),
				})
			},
			method:              http.MethodPut,
			name:                "update configuration with explicit false",
			path:                "/control/stats/config/update",
			query:               "",
			requestBody:         `{"enabled":false,"interval":0,"ignored":[],"ignored_enabled":false}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutStatsConfig(ctx, adguard.StatsConfig{
					Enabled:        true,
					Interval:       3_600_000,
					Ignored:        []string{"router.local"},
					IgnoredEnabled: new(true),
				})
			},
			method: http.MethodPut,
			name:   "update configuration with explicit true",
			path:   "/control/stats/config/update",
			query:  "",
			requestBody: `{"enabled":true,"interval":3600000,` +
				`"ignored":["router.local"],"ignored_enabled":true}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
		},
	}
}

// statsIntegrationOperations returns every statistics operation for transport tests.
//
// Returns:
//   - The read, reset, configuration-read, and configuration-update operations.
func statsIntegrationOperations() []statsIntegrationOperation {
	return []statsIntegrationOperation{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.Stats(ctx, &adguard.StatsRequest{Recent: new(int64(-1))})

				return err
			},
			method:    http.MethodGet,
			name:      "statistics",
			operation: "stats",
			path:      "/control/stats",
			query:     "recent=-1",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.StatsReset(ctx)
			},
			method:    http.MethodPost,
			name:      "reset",
			operation: "stats_reset",
			path:      "/control/stats_reset",
			query:     "",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetStatsConfig(ctx)

				return err
			},
			method:    http.MethodGet,
			name:      "read configuration",
			operation: "get_stats_config",
			path:      "/control/stats/config",
			query:     "",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.PutStatsConfig(ctx, adguard.StatsConfig{Ignored: []string{}})
			},
			method:    http.MethodPut,
			name:      "update configuration",
			operation: "put_stats_config",
			path:      "/control/stats/config/update",
			query:     "",
		},
	}
}

// statsIntegrationResponseErrorCases returns invalid statistics JSON response cases.
//
// Returns:
//   - Malformed, empty, null, schema-invalid, and media-type response cases.
func statsIntegrationResponseErrorCases() []statsIntegrationResponseErrorCase {
	statisticsCall := func(ctx context.Context, client *adguard.Client) error {
		_, err := client.Stats(ctx, nil)

		return err
	}
	configCall := func(ctx context.Context, client *adguard.Client) error {
		_, err := client.GetStatsConfig(ctx)

		return err
	}

	return []statsIntegrationResponseErrorCase{
		{
			body:        `{"time_units":`,
			call:        statisticsCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "malformed statistics",
			operation:   "stats",
		},
		{
			body:        "",
			call:        statisticsCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "empty statistics response",
			operation:   "stats",
		},
		{
			body:        "null",
			call:        statisticsCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "null statistics",
			operation:   "stats",
		},
		{
			body:        `{"time_units":"minutes"}`,
			call:        statisticsCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "invalid time unit",
			operation:   "stats",
		},
		{
			body:            `{}`,
			call:            statisticsCall,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			method:          http.MethodGet,
			name:            "statistics media type",
			operation:       "stats",
			wantContentType: "text/plain",
		},
		{
			body:        `{"enabled":`,
			call:        configCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "malformed configuration",
			operation:   "get_stats_config",
		},
		{
			body:        "",
			call:        configCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "empty configuration response",
			operation:   "get_stats_config",
		},
		{
			body:        "null",
			call:        configCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "null configuration",
			operation:   "get_stats_config",
		},
		{
			body:        `{"interval":0,"ignored":[]}`,
			call:        configCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "missing enabled",
			operation:   "get_stats_config",
		},
		{
			body:        `{"enabled":true,"interval":0}`,
			call:        configCall,
			contentType: statsIntegrationJSONMediaType,
			kind:        adguard.ErrorKindJSON,
			method:      http.MethodGet,
			name:        "missing ignored",
			operation:   "get_stats_config",
		},
		{
			body:            statsIntegrationConfigResponse,
			call:            configCall,
			contentType:     "text/plain",
			kind:            adguard.ErrorKindContentType,
			method:          http.MethodGet,
			name:            "configuration media type",
			operation:       "get_stats_config",
			wantContentType: "text/plain",
		},
	}
}

// runStatsIntegrationRequestContract verifies one successful request contract.
//
// Parameters:
//   - contract: The request and response contract to exercise.
func runStatsIntegrationRequestContract(t *testing.T, contract *statsIntegrationRequestContract) {
	t.Helper()

	captured := make(chan statsIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureStatsIntegrationRequest(r)

		writeStatsIntegrationResponse(
			w,
			contract.responseContentType,
			contract.status,
			contract.responseBody,
		)
	}))
	client := newStatsIntegrationClient(t, server, 16<<10)

	err := contract.call(t.Context(), client)

	require.NoError(t, err)
	assertStatsIntegrationRequest(t, contract, <-captured)
}

// runStatsIntegrationStatusError verifies one structured non-success response.
//
// Parameters:
//   - operation: The statistics operation to exercise.
func runStatsIntegrationStatusError(t *testing.T, operation statsIntegrationOperation) {
	t.Helper()

	captured := make(chan statsIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureStatsIntegrationRequest(r)

		writeStatsIntegrationResponse(
			w,
			statsIntegrationProblemMediaType,
			http.StatusUnprocessableEntity,
			statsIntegrationErrorBody,
		)
	}))
	client := newStatsIntegrationClient(t, server, 4096)

	err := operation.call(t.Context(), client)

	clientErr := requireStatsIntegrationError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, operation.operation, clientErr.Operation)
	assert.Equal(t, operation.method, clientErr.Method)
	assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
	assert.Equal(t, "422 Unprocessable Entity", clientErr.Status)
	assert.Equal(t, statsIntegrationProblemMediaType, clientErr.ContentType)
	assert.JSONEq(t, statsIntegrationErrorBody, string(clientErr.Body))
	assert.NoError(t, clientErr.Err)

	request := <-captured
	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, operation.method, request.method)
	assert.Equal(t, operation.path, request.path)
	assert.Equal(t, operation.query, request.query)
	assertStatsIntegrationAuthentication(t, request)
}

// newStatsIntegrationResponseServer creates a fixed statistics response server.
//
// Parameters:
//   - contentType: The response media type.
//   - body: The response body, or an empty string for no body.
//
// Returns:
//   - server: The HTTP test server.
func newStatsIntegrationResponseServer(
	t *testing.T,
	contentType string,
	body string,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeStatsIntegrationResponse(w, contentType, http.StatusOK, body)
	}))
}

// newStatsIntegrationClient creates a concrete client bound to a test server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - limit: The maximum accepted response body size.
//
// Returns:
//   - client: The configured AdGuard client.
func newStatsIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		statsIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(statsIntegrationUsername, statsIntegrationPassword),
		adguard.WithUserAgent(statsIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// captureStatsIntegrationRequest reads and records one statistics request.
//
// Parameters:
//   - request: The HTTP request captured by the test server.
//
// Returns:
//   - capture: The request metadata and body-consumption errors.
func captureStatsIntegrationRequest(
	request *http.Request,
) statsIntegrationRequestCapture {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	username, password, hasAuth := request.BasicAuth()

	return statsIntegrationRequestCapture{
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

// assertStatsIntegrationRequest verifies one captured request contract.
//
// Parameters:
//   - contract: The expected request contract.
//   - request: The captured request metadata.
func assertStatsIntegrationRequest(
	t *testing.T,
	contract *statsIntegrationRequestContract,
	request statsIntegrationRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, contract.method, request.method)
	assert.Equal(t, contract.path, request.path)
	assert.Equal(t, contract.query, request.query)
	//nolint:testifylint // encoded-compare: Exact HTTP header equality is required.
	assert.Equal(t, statsIntegrationJSONMediaType, request.accept)
	assert.Equal(t, statsIntegrationUserAgent, request.userAgent)
	assertStatsIntegrationAuthentication(t, request)

	if contract.requestBody == "" {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.body)
		assert.Empty(t, request.contentType)

		return
	}

	assert.Positive(t, request.contentLength)
	//nolint:testifylint // encoded-compare: Exact HTTP header equality is required.
	assert.Equal(t, statsIntegrationJSONMediaType, request.contentType)
	assert.JSONEq(t, contract.requestBody, string(request.body))
}

// assertStatsIntegrationAuthentication verifies exact Basic Auth credentials.
//
// Parameters:
//   - request: The captured request metadata.
func assertStatsIntegrationAuthentication(
	t *testing.T,
	request statsIntegrationRequestCapture,
) {
	t.Helper()

	assert.True(t, request.hasAuth)
	assert.Equal(t, statsIntegrationUsername, request.username)
	assert.Equal(t, statsIntegrationPassword, request.password)
}

// writeStatsIntegrationResponse writes one complete HTTP response.
//
// Parameters:
//   - writer: The response writer receiving the response.
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP status code.
//   - body: The response body, or an empty string for no body.
func writeStatsIntegrationResponse(
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

// requireStatsIntegrationError extracts a structured statistics client error.
//
// Parameters:
//   - err: The operation error to inspect.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireStatsIntegrationError(
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
