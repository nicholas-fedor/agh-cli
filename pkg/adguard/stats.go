// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// StatsService exposes DNS statistics and statistics configuration operations.
//
// The final two methods are the deprecated legacy statistics operations.
type StatsService interface {
	GetStatsConfig(ctx context.Context) (*StatsConfig, error)
	PutStatsConfig(ctx context.Context, config StatsConfig) error
	Stats(ctx context.Context, request *StatsRequest) (*Stats, error)
	StatsReset(ctx context.Context) error

	// Deprecated: Use GetStatsConfig instead.
	StatsInfo(ctx context.Context) (*StatsConfig, error)
	// Deprecated: Use PutStatsConfig instead.
	StatsConfig(ctx context.Context, config StatsConfig) error
}

// StatsRequest selects the statistics lookback period.
type StatsRequest struct {
	// Recent optionally sets the lookback period in milliseconds. Nil omits the
	// recent query parameter, while a nonnil pointer sends its value, including
	// zero. The server validates the documented one-hour and configured-interval
	// constraints.
	Recent *int64
}

// StatsTimeUnit is the time unit used by a statistics response.
type StatsTimeUnit string

// StatsEntry maps one domain, client, or upstream to its reported count or
// processing time. A nil map represents a JSON null list entry.
type StatsEntry map[string]float64

// Stats contains DNS server statistics.
//
// Every field is optional because the pinned schema requires none. Nil scalar
// and slice pointers represent an absent or null value. Nonnil pointers preserve
// explicit zero values and empty lists. A present TimeUnits value must be
// StatsTimeUnitHours or StatsTimeUnitDays.
type Stats struct {
	// TimeUnits is the optional statistics time unit.
	TimeUnits *StatsTimeUnit `json:"time_units,omitzero"`
	// NumDNSQueries is the optional total number of DNS queries.
	NumDNSQueries *int64 `json:"num_dns_queries,omitzero"`
	// NumBlockedFiltering is the optional number of requests blocked by
	// filtering rules.
	NumBlockedFiltering *int64 `json:"num_blocked_filtering,omitzero"`
	// NumReplacedSafebrowsing is the optional number of requests blocked by
	// safe browsing.
	NumReplacedSafebrowsing *int64 `json:"num_replaced_safebrowsing,omitzero"`
	// NumReplacedSafesearch is the optional number of requests blocked by safe
	// search.
	NumReplacedSafesearch *int64 `json:"num_replaced_safesearch,omitzero"`
	// NumReplacedParental is the optional number of requests blocked by
	// parental control.
	NumReplacedParental *int64 `json:"num_replaced_parental,omitzero"`
	// AvgProcessingTime is the optional average DNS request processing time in
	// seconds.
	AvgProcessingTime *float64 `json:"avg_processing_time,omitzero"`
	// TopQueriedDomains contains optional top queried-domain entries.
	TopQueriedDomains *[]StatsEntry `json:"top_queried_domains,omitzero"`
	// TopClients contains optional top-client entries.
	TopClients *[]StatsEntry `json:"top_clients,omitzero"`
	// TopBlockedDomains contains optional top blocked-domain entries.
	TopBlockedDomains *[]StatsEntry `json:"top_blocked_domains,omitzero"`
	// TopUpstreamsResponses contains optional response counts for each upstream.
	TopUpstreamsResponses *[]StatsEntry `json:"top_upstreams_responses,omitzero"`
	// TopUpstreamsAvgTime contains optional average processing times for each
	// upstream.
	TopUpstreamsAvgTime *[]StatsEntry `json:"top_upstreams_avg_time,omitzero"`
	// DNSQueries contains optional per-period DNS query counts.
	DNSQueries *[]int64 `json:"dns_queries,omitzero"`
	// BlockedFiltering contains optional per-period filtering block counts.
	BlockedFiltering *[]int64 `json:"blocked_filtering,omitzero"`
	// ReplacedSafebrowsing contains optional per-period safe-browsing block
	// counts.
	ReplacedSafebrowsing *[]int64 `json:"replaced_safebrowsing,omitzero"`
	// ReplacedParental contains optional per-period parental-control block
	// counts.
	ReplacedParental *[]int64 `json:"replaced_parental,omitzero"`
}

// StatsConfig contains DNS statistics configuration.
//
// Enabled, Interval, and Ignored are required and are always serialized by
// PutStatsConfig. IgnoredEnabled is optional; nil omits it from an update and
// represents an absent or null response value. A nonnil IgnoredEnabled preserves
// an explicit false value.
type StatsConfig struct {
	// Enabled reports or sets whether statistics are enabled.
	Enabled bool `json:"enabled"`
	// Interval is the statistics rotation interval in milliseconds.
	Interval float64 `json:"interval"`
	// Ignored contains host names that statistics may exclude. A nil slice is
	// rejected by PutStatsConfig; a nonnil empty slice is sent as an empty array.
	Ignored []string `json:"ignored"`
	// IgnoredEnabled optionally controls whether Ignored is excluded.
	IgnoredEnabled *bool `json:"ignored_enabled,omitzero"`
}

const (
	// StatsTimeUnitHours identifies hourly statistics buckets.
	StatsTimeUnitHours StatsTimeUnit = "hours"
	// StatsTimeUnitDays identifies daily statistics buckets.
	StatsTimeUnitDays StatsTimeUnit = "days"
)

const (
	// Statistics operation identifies Stats errors.
	statsOperation = "stats"
	// Statistics reset operation identifies StatsReset errors.
	statsResetOperation = "stats_reset"
	// Statistics configuration read identifies GetStatsConfig errors.
	getStatsConfigOperation = "get_stats_config"
	// Statistics configuration write identifies PutStatsConfig errors.
	putStatsConfigOperation = "put_stats_config"
	// Maximum upstream list length in one statistics response.
	statsMaxUpstreamEntries = 100
)

var (
	// ErrNullStatsResponse identifies a top-level null statistics response.
	errNullStatsResponse = errors.New("statistics response must be a JSON object")
	// ErrNullStatsConfigResponse identifies a top-level null configuration response.
	errNullStatsConfigResponse = errors.New("statistics configuration response must be a JSON object")
	// ErrRequiredStatsConfigField identifies an absent or null required field.
	errRequiredStatsConfigField = errors.New("required statistics configuration field is missing")
	// ErrInvalidStatsTimeUnit identifies an unsupported statistics time unit.
	errInvalidStatsTimeUnit = errors.New("invalid statistics time unit")
	// ErrStatsUpstreamEntriesLimit identifies an oversized upstream statistics list.
	errStatsUpstreamEntriesLimit = errors.New("statistics upstream entries exceed schema limit")
)

var _ StatsService = (*Client)(nil)

// GetStatsConfig retrieves the DNS statistics configuration.
//
// The successful response must use a JSON media type and contain a non-null
// object with present, non-null enabled, interval, and ignored fields. The
// optional ignored_enabled field may be absent or null.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - config: The decoded statistics configuration when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, null-object, or missing-required-field failures;
//     otherwise nil.
func (c *Client) GetStatsConfig(ctx context.Context) (*StatsConfig, error) {
	response, requestErr := c.get(ctx, getStatsConfigOperation, "control/stats/config")
	if requestErr != nil {
		return nil, requestErr
	}

	var wireConfig *struct {
		Enabled        *bool     `json:"enabled"`
		Interval       *float64  `json:"interval"`
		Ignored        *[]string `json:"ignored"`
		IgnoredEnabled *bool     `json:"ignored_enabled"`
	}

	err := json.Unmarshal(response.body, &wireConfig)
	if err != nil {
		return nil, statsJSONError(
			getStatsConfigOperation,
			fmt.Errorf("decode response: %w", err),
		)
	}

	if wireConfig == nil {
		return nil, statsJSONError(getStatsConfigOperation, errNullStatsConfigResponse)
	}

	switch {
	case wireConfig.Enabled == nil:
		return nil, statsJSONError(
			getStatsConfigOperation,
			fmt.Errorf("%w: enabled", errRequiredStatsConfigField),
		)
	case wireConfig.Interval == nil:
		return nil, statsJSONError(
			getStatsConfigOperation,
			fmt.Errorf("%w: interval", errRequiredStatsConfigField),
		)
	case wireConfig.Ignored == nil:
		return nil, statsJSONError(
			getStatsConfigOperation,
			fmt.Errorf("%w: ignored", errRequiredStatsConfigField),
		)
	default:
	}

	return &StatsConfig{
		Enabled:        *wireConfig.Enabled,
		Interval:       *wireConfig.Interval,
		Ignored:        *wireConfig.Ignored,
		IgnoredEnabled: wireConfig.IgnoredEnabled,
	}, nil
}

// PutStatsConfig replaces the DNS statistics configuration.
//
// The request body is always present as a JSON object. Enabled and Interval are
// always serialized, including false and zero. Ignored must be nonnil and is
// serialized as its exact list, preserving an explicit empty list. A nil
// IgnoredEnabled omits the optional field, while a nonnil pointer preserves false
// or true. Any 2xx response is accepted without interpreting its body, but the
// response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The complete statistics configuration to apply.
//
// Returns:
//   - err: An *Error for a missing required list, request, redirect, HTTP,
//     response-limit, response-body, or encoding failure; otherwise nil.
func (c *Client) PutStatsConfig(ctx context.Context, config StatsConfig) error {
	if config.Ignored == nil {
		requestErr := responseError(
			putStatsConfigOperation,
			ErrorKindRequest,
			nil,
			fmt.Errorf("%w: ignored", errRequiredStatsConfigField),
		)

		requestErr.Method = http.MethodPut

		return requestErr
	}

	requestErr := c.postEmpty(
		ctx,
		putStatsConfigOperation,
		http.MethodPut,
		"control/stats/config/update",
		config,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// Stats retrieves DNS server statistics.
//
// A nil request or nil Recent field omits the recent query parameter. A nonnil
// Recent value is encoded exactly, including zero or a negative value; the
// server is responsible for the documented semantic validation. The successful
// response must use a JSON media type and contain a non-null object.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional statistics query parameters.
//
// Returns:
//   - statistics: The decoded statistics when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, null-object, invalid-time-unit, or
//     upstream-list-limit failures; otherwise nil.
func (c *Client) Stats(ctx context.Context, request *StatsRequest) (*Stats, error) {
	response, requestErr := c.getStats(ctx, request)
	if requestErr != nil {
		return nil, requestErr
	}

	var statistics *Stats

	err := json.Unmarshal(response.body, &statistics)
	if err != nil {
		return nil, statsJSONError(
			statsOperation,
			fmt.Errorf("decode response: %w", err),
		)
	}
	if statistics == nil {
		return nil, statsJSONError(statsOperation, errNullStatsResponse)
	}

	err = validateStats(statistics)
	if err != nil {
		return nil, statsJSONError(statsOperation, err)
	}

	return statistics, nil
}

// StatsReset resets all DNS server statistics to zero.
//
// The request has no body. Any 2xx response is accepted without interpreting its
// body or media type, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) StatsReset(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, statsResetOperation, "control/stats_reset")
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// getStats executes a bounded statistics GET request with optional query
// parameters.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - statsRequest: The optional statistics query parameters.
//
// Returns:
//   - response: The bounded, validated JSON response body.
//   - err: An *Error for request, redirect, status, response-size,
//     response-body, or media-type failures; otherwise nil.
func (c *Client) getStats(
	ctx context.Context,
	statsRequest *StatsRequest,
) (*apiResponse, *Error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newRequest(requestContext, statsOperation, "control/stats")
	if requestErr != nil {
		cancel()

		return nil, requestErr
	}

	if statsRequest != nil && statsRequest.Recent != nil {
		request.URL.RawQuery = "recent=" + strconv.FormatInt(*statsRequest.Recent, 10)
	}

	response, requestErr := c.executeRequest(requestContext, statsOperation, request)
	if requestErr != nil {
		cancel()

		return nil, requestErr
	}

	apiResponse, responseErr := readAPIResponse(statsOperation, response, c.maxResponseBytes)

	cancel()

	return apiResponse, responseErr
}

// statsJSONError creates a structured statistics JSON or contract error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - cause: The decoding or response-contract cause.
//
// Returns:
//   - err: The structured JSON error.
func statsJSONError(operation string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = http.MethodGet
	clientErr.Err = cause

	return clientErr
}

// validateStats validates constrained statistics response fields.
//
// Parameters:
//   - statistics: The decoded statistics response. It must not be nil.
//
// Returns:
//   - err: An invalid-time-unit or upstream-list-limit error; otherwise nil.
func validateStats(statistics *Stats) error {
	if statistics.TimeUnits != nil {
		switch *statistics.TimeUnits {
		case StatsTimeUnitHours, StatsTimeUnitDays:
		default:
			return errInvalidStatsTimeUnit
		}
	}

	if statistics.TopUpstreamsResponses != nil &&
		len(*statistics.TopUpstreamsResponses) > statsMaxUpstreamEntries {
		return errStatsUpstreamEntriesLimit
	}
	if statistics.TopUpstreamsAvgTime != nil &&
		len(*statistics.TopUpstreamsAvgTime) > statsMaxUpstreamEntries {
		return errStatsUpstreamEntriesLimit
	}

	return nil
}
