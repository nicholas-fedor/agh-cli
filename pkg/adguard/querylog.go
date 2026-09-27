// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
)

// QueryLogService exposes the query-log read, clear, and configuration
// operations.
type QueryLogService interface {
	QueryLog(ctx context.Context, request *QueryLogRequest) (*QueryLog, error)
	QueryLogClear(ctx context.Context) error
	GetQueryLogConfig(ctx context.Context) (*QueryLogConfig, error)
	PutQueryLogConfig(ctx context.Context, config QueryLogConfig) error

	// Deprecated: Use GetQueryLogConfig instead.
	QueryLogInfo(ctx context.Context) (*QueryLogConfig, error)
	// Deprecated: Use PutQueryLogConfig instead.
	QueryLogConfig(ctx context.Context, config QueryLogConfig) error
}

// QueryLogRequest contains the optional query-log filters.
//
// Every member is optional. A nil pointer or nil slice omits the corresponding
// query parameter, while a nonnil pointer sends the value explicitly, including
// zero and an empty string.
type QueryLogRequest struct {
	// OlderThan returns entries older than the RFC 3339 timestamp when set.
	OlderThan *string
	// Offset is the number of entries to skip.
	Offset *int32
	// Limit is the maximum number of entries to return.
	Limit *int32
	// Search matches entries against the supplied substring.
	Search *string
	// Reasons restricts entries to the supplied filtering reasons. Each reason
	// must be a valid filtering reason.
	Reasons []FilteringReason
}

// QueryLog is a page of query-log entries returned by GET /control/querylog.
type QueryLog struct {
	// Oldest is the RFC 3339 timestamp of the oldest available entry, or nil
	// when the response omitted it or returned null.
	Oldest *string `json:"oldest"`
	// Data contains the page of entries, or nil when the response omitted it or
	// returned null.
	Data *[]QueryLogEntry `json:"data"`
}

// QueryLogEntry is one query-log record.
//
// Every member is optional. A nil pointer means that the server omitted the
// member or returned JSON null, and a nonnil pointer preserves an explicit
// false, zero, or empty value.
type QueryLogEntry struct {
	// Answer contains the response answers returned by the upstream server.
	Answer *[]*DNSAnswer `json:"answer"`
	// OriginalAnswer contains the answers before the rewrite rules applied.
	OriginalAnswer *[]*DNSAnswer `json:"original_answer"`
	// Cached reports whether the answer came from the cache.
	Cached *bool `json:"cached"`
	// Upstream is the upstream server address.
	Upstream *string `json:"upstream"`
	// AnswerDNSSEC reports whether the answer carried DNSSEC data.
	AnswerDNSSEC *bool `json:"answer_dnssec"`
	// Client is the client address.
	Client *string `json:"client"`
	// ClientID is the persistent client identifier.
	ClientID *string `json:"client_id"`
	// ClientInfo contains the resolved client details.
	ClientInfo *QueryLogClient `json:"client_info"`
	// ClientProtocol is the protocol used by the client.
	ClientProtocol *string `json:"client_proto"`
	// ECS is the EDNS client subnet reported by the client.
	ECS *string `json:"ecs"`
	// ElapsedMS is the processing duration in milliseconds.
	ElapsedMS *string `json:"elapsedMs"`
	// Question contains the question the entry answers.
	Question *DNSQuestion `json:"question"`
	// FilterID is the identifier of the filter that produced the rule.
	FilterID *int32 `json:"filterId"`
	// Rule is the single rewrite rule text that matched the query.
	Rule *string `json:"rule"`
	// Rules contains the rewrite rules that matched the query.
	Rules *[]*QueryLogRule `json:"rules"`
	// Reason is the filtering reason recorded for the entry.
	Reason *FilteringReason `json:"reason"`
	// ServiceName is the blocked-service name recorded for the entry.
	ServiceName *string `json:"service_name"`
	// Status is the processing status recorded for the entry.
	Status *string `json:"status"`
	// Time is the RFC 3339 timestamp of the entry.
	Time *string `json:"time"`
}

// DNSAnswer is one resource record returned for a query-log question.
type DNSAnswer struct {
	// TTL is the record time to live in seconds.
	TTL *int32 `json:"ttl"`
	// Type is the record type.
	Type *string `json:"type"`
	// Value is the record value.
	Value *string `json:"value"`
}

// DNSQuestion is the question a query-log entry answers.
type DNSQuestion struct {
	// Class is the question class.
	Class *string `json:"class"`
	// Name is the queried domain name.
	Name *string `json:"name"`
	// UnicodeName is the IDNA-encoded form of Name.
	UnicodeName *string `json:"unicode_name"`
	// Type is the question type.
	Type *string `json:"type"`
}

// QueryLogRule is one rewrite rule recorded on a query-log entry.
type QueryLogRule struct {
	// FilterListID is the identifier of the filter list that owns the rule.
	FilterListID *int64 `json:"filter_list_id"`
	// Text is the rewrite rule text.
	Text *string `json:"text"`
}

// QueryLogClient contains the resolved details of the client that issued a
// query.
type QueryLogClient struct {
	// Disallowed reports whether the client name matches a blocked-client rule.
	Disallowed bool `json:"disallowed"`
	// DisallowedRule is the blocked-client rule that matched the client name.
	DisallowedRule string `json:"disallowed_rule"`
	// Name is the resolved client name.
	Name string `json:"name"`
	// Whois contains the optional WHOIS details for the client address.
	Whois *QueryLogClientWhois `json:"whois"`
}

// QueryLogClientWhois contains the WHOIS details resolved for a client address.
type QueryLogClientWhois struct {
	// City is the registrant city.
	City *string `json:"city"`
	// Country is the registrant country.
	Country *string `json:"country"`
	// Organization is the registrant organization.
	Organization *string `json:"orgname"`
}

// QueryLogConfig is the query-log configuration returned by
// GET /control/querylog/config.
type QueryLogConfig struct {
	// Enabled reports whether query-log recording is enabled.
	Enabled bool `json:"enabled"`
	// Interval is the query-log rotation interval in days.
	Interval float64 `json:"interval"`
	// AnonymizeClientIP reports whether client addresses are anonymized.
	AnonymizeClientIP bool `json:"anonymize_client_ip"`
	// Ignored contains the logged domain names to ignore.
	Ignored []string `json:"ignored"`
	// IgnoredEnabled is the optional companion setting for Ignored. Nil omits
	// the field, while a nonnil pointer sends an explicit false value.
	IgnoredEnabled *bool `json:"ignored_enabled,omitzero"`
}

// queryLogResponse mirrors the pinned query-log response schema.
//
// Pointer fields keep the difference between an absent or null value and a
// present value so that a null response body can be reported distinctly.
type queryLogResponse struct {
	// Oldest is nil when the timestamp is absent or null.
	Oldest *string `json:"oldest"`
	// Data is nil when the entry list is absent or null.
	Data *[]*queryLogEntryResponse `json:"data"`
}

// queryLogEntryResponse mirrors the pinned query-log entry schema.
//
// ClientInfo is decoded separately because the response nests pointers for its
// required members, which the public value model resolves to plain values.
type queryLogEntryResponse struct {
	// Answer is nil when the answer list is absent or null.
	Answer *[]*DNSAnswer `json:"answer"`
	// OriginalAnswer is nil when the original answer list is absent or null.
	OriginalAnswer *[]*DNSAnswer `json:"original_answer"`
	// Cached is nil when the cache state is absent or null.
	Cached *bool `json:"cached"`
	// Upstream is nil when the upstream address is absent or null.
	Upstream *string `json:"upstream"`
	// AnswerDNSSEC is nil when the DNSSEC state is absent or null.
	AnswerDNSSEC *bool `json:"answer_dnssec"`
	// Client is nil when the client address is absent or null.
	Client *string `json:"client"`
	// ClientID is nil when the client identifier is absent or null.
	ClientID *string `json:"client_id"`
	// ClientInfo is nil when the client details are absent or null.
	ClientInfo *queryLogClientResponse `json:"client_info"`
	// ClientProtocol is nil when the client protocol is absent or null.
	ClientProtocol *string `json:"client_proto"`
	// ECS is nil when the EDNS client subnet is absent or null.
	ECS *string `json:"ecs"`
	// ElapsedMS is nil when the processing duration is absent or null.
	ElapsedMS *string `json:"elapsedMs"`
	// Question is nil when the question is absent or null.
	Question *DNSQuestion `json:"question"`
	// FilterID is nil when the filter identifier is absent or null.
	FilterID *int32 `json:"filterId"`
	// Rule is nil when the rewrite rule text is absent or null.
	Rule *string `json:"rule"`
	// Rules is nil when the rewrite rule list is absent or null.
	Rules *[]*QueryLogRule `json:"rules"`
	// Reason is nil when the filtering reason is absent or null.
	Reason *FilteringReason `json:"reason"`
	// ServiceName is nil when the blocked-service name is absent or null.
	ServiceName *string `json:"service_name"`
	// Status is nil when the processing status is absent or null.
	Status *string `json:"status"`
	// Time is nil when the entry timestamp is absent or null.
	Time *string `json:"time"`
}

// queryLogClientResponse mirrors the pinned client-details schema.
//
// Every member is required, so each field is a pointer that is nil when the
// server omitted the member or returned JSON null.
type queryLogClientResponse struct {
	// Disallowed is nil when the blocked-client state is absent or null.
	Disallowed *bool `json:"disallowed"`
	// DisallowedRule is nil when the matched rule is absent or null.
	DisallowedRule *string `json:"disallowed_rule"`
	// Name is nil when the client name is absent or null.
	Name *string `json:"name"`
	// Whois is nil when the WHOIS details are absent or null.
	Whois *QueryLogClientWhois `json:"whois"`
}

// queryLogConfigResponse mirrors the pinned query-log configuration schema.
//
// Every member is required, so each field is a pointer that is nil when the
// server omitted the member or returned JSON null.
type queryLogConfigResponse struct {
	// Enabled is nil when the query-log state is absent or null.
	Enabled *bool `json:"enabled"`
	// Interval is nil when the rotation interval is absent or null.
	Interval *float64 `json:"interval"`
	// AnonymizeClientIP is nil when the anonymization state is absent or null.
	AnonymizeClientIP *bool `json:"anonymize_client_ip"`
	// Ignored is nil when the ignored-domain list is absent or null.
	Ignored *[]string `json:"ignored"`
	// IgnoredEnabled is nil when the companion setting is absent or null.
	IgnoredEnabled *bool `json:"ignored_enabled"`
}

const (
	// QueryLogOperation identifies query-log retrieval.
	queryLogOperation = "query_log"
	// QueryLogClearOperation identifies query-log clearing.
	queryLogClearOperation = "query_log_clear"
	// GetQueryLogConfigOperation identifies query-log configuration retrieval.
	getQueryLogConfigOperation = "get_query_log_config"
	// PutQueryLogConfigOperation identifies query-log configuration updates.
	putQueryLogConfigOperation = "put_query_log_config"
	// QueryLogEndpoint is the query-log retrieval path.
	queryLogEndpoint = "control/querylog"
	// QueryLogClearEndpoint is the query-log clearing path.
	queryLogClearEndpoint = "control/querylog_clear"
	// GetQueryLogConfigEndpoint is the query-log configuration retrieval path.
	getQueryLogConfigEndpoint = "control/querylog/config"
	// PutQueryLogConfigEndpoint is the query-log configuration update path.
	putQueryLogConfigEndpoint = "control/querylog/config/update"
)

var (
	_ QueryLogService = (*Client)(nil)

	// ErrRequiredQueryLogField identifies an absent required query-log field.
	errRequiredQueryLogField = errors.New("required query log field is missing")
	// ErrInvalidQueryLogReason identifies an unsupported filtering reason.
	errInvalidQueryLogReason = errors.New("invalid query log reason")
	// ErrNullQueryLogResponse identifies a null query-log response object.
	errNullQueryLogResponse = errors.New("query log response must be a JSON object")
)

// queryLogQuery converts a request into query parameters.
//
// Parameters:
//   - request: The optional query-log filters. A nil request produces an empty
//     parameter set.
//
// Returns:
//   - query: The encoded query parameters when every reason is valid.
//   - err: An invalid-filtering-reason error; otherwise nil.
func queryLogQuery(request *QueryLogRequest) (url.Values, error) {
	query := make(url.Values, 5)

	if request == nil {
		return query, nil
	}

	setQueryLogFilterValues(query, request)

	err := addQueryLogReasons(query, request.Reasons)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return query, nil
}

// setQueryLogFilterValues sets the optional single-valued query-log filters.
//
// A nil pointer omits its parameter, while a nonnil pointer sends the value
// explicitly, including zero and an empty string.
//
// Parameters:
//   - query: The query parameters to populate.
//   - request: The decoded query-log filters holding the optional values.
func setQueryLogFilterValues(query url.Values, request *QueryLogRequest) {
	if request.OlderThan != nil {
		query.Set("older_than", *request.OlderThan)
	}
	if request.Offset != nil {
		query.Set("offset", strconv.FormatInt(int64(*request.Offset), 10))
	}
	if request.Limit != nil {
		query.Set("limit", strconv.FormatInt(int64(*request.Limit), 10))
	}
	if request.Search != nil {
		query.Set("search", *request.Search)
	}
}

// addQueryLogReasons appends the validated filtering-reason query-log filters.
//
// Parameters:
//   - query: The query parameters to populate.
//   - reasons: The requested filtering reasons.
//
// Returns:
//   - err: An invalid-filtering-reason error; otherwise nil.
func addQueryLogReasons(query url.Values, reasons []FilteringReason) error {
	for _, reason := range reasons {
		if !validFilteringReason(reason) {
			return fmt.Errorf("%s: %w", reason, errInvalidQueryLogReason)
		}

		query.Add("reason", string(reason))
	}

	return nil
}

// QueryLog retrieves a page of query-log entries.
//
// The request is GET /control/querylog with the filters encoded as query
// parameters. The response must be a JSON object, and every entry must declare
// a valid filtering reason when it reports one.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional query-log filters.
//
// Returns:
//   - log: The decoded query-log page when the response is valid.
//   - err: An [Error] for request, redirect, HTTP, response-limit,
//     response-body, media-type, JSON, or response-contract failures;
//     otherwise nil.
func (c *Client) QueryLog(ctx context.Context, request *QueryLogRequest) (*QueryLog, error) {
	query, err := queryLogQuery(request)
	if err != nil {
		return nil, queryLogRequestError(queryLogOperation, http.MethodGet, err)
	}

	response, requestErr := c.getQueryLogJSON(
		ctx,
		queryLogOperation,
		queryLogEndpoint,
		query,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var wire *queryLogResponse

	err = json.Unmarshal(response.body, &wire)
	if err != nil {
		return nil, queryLogJSONError(queryLogOperation, fmt.Errorf("decode response: %w", err))
	}
	if wire == nil {
		return nil, queryLogJSONError(queryLogOperation, errNullQueryLogResponse)
	}

	log, err := queryLogFromWire(*wire)
	if err != nil {
		return nil, queryLogJSONError(queryLogOperation, err)
	}

	return log, nil
}

// QueryLogClear removes the recorded query-log entries.
//
// The request is POST /control/querylog_clear. The response is treated as an
// empty response mode: its body is bounded and closed but is not decoded, and
// its media type is not required.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An [Error] for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) QueryLogClear(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, queryLogClearOperation, queryLogClearEndpoint)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// GetQueryLogConfig retrieves the query-log configuration.
//
// The request is GET /control/querylog/config. The response must be a JSON
// object containing the required enabled, interval, anonymize_client_ip, and
// ignored members.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - config: The decoded query-log configuration when the response is valid.
//   - err: An [Error] for request, redirect, HTTP, response-limit,
//     response-body, media-type, JSON, or required-field failures; otherwise
//     nil.
func (c *Client) GetQueryLogConfig(ctx context.Context) (*QueryLogConfig, error) {
	response, requestErr := c.getQueryLogJSON(
		ctx,
		getQueryLogConfigOperation,
		getQueryLogConfigEndpoint,
		nil,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var wire *queryLogConfigResponse

	err := json.Unmarshal(response.body, &wire)
	if err != nil {
		return nil, queryLogJSONError(
			getQueryLogConfigOperation,
			fmt.Errorf("decode response: %w", err),
		)
	}
	if wire == nil {
		return nil, queryLogJSONError(getQueryLogConfigOperation, errNullQueryLogResponse)
	}

	config, err := queryLogConfigFromWire(*wire)
	if err != nil {
		return nil, queryLogJSONError(getQueryLogConfigOperation, err)
	}

	return config, nil
}

// PutQueryLogConfig applies the query-log configuration.
//
// The request is PUT /control/querylog/config/update and always contains a JSON
// configuration object. A nil Ignored slice is rejected, because the request
// contract requires the ignored member. The response is treated as an empty
// response mode: its body is bounded and closed but is not decoded, and its
// media type is not required.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The query-log configuration to apply.
//
// Returns:
//   - err: An [Error] for a missing required field, encoding, request,
//     redirect, HTTP, response-limit, or response-body failures; otherwise nil.
func (c *Client) PutQueryLogConfig(ctx context.Context, config QueryLogConfig) error {
	if config.Ignored == nil {
		return queryLogRequestError(
			putQueryLogConfigOperation,
			http.MethodPut,
			fmt.Errorf("ignored: %w", errRequiredQueryLogField),
		)
	}

	requestErr := c.postEmpty(
		ctx,
		putQueryLogConfigOperation,
		http.MethodPut,
		putQueryLogConfigEndpoint,
		config,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// getQueryLogJSON performs a bounded GET request for a query-log endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on errors.
//   - endpoint: The request path appended to the API prefix.
//   - query: The encoded query parameters, which may be nil.
//
// Returns:
//   - response: The bounded response body when the request succeeds.
//   - err: A structured request, redirect, HTTP, response-limit, or
//     response-body error; otherwise nil.
func (c *Client) getQueryLogJSON(
	ctx context.Context,
	operation string,
	endpoint string,
	query url.Values,
) (*apiResponse, *Error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newRequest(requestContext, operation, endpoint)
	if requestErr != nil {
		cancel()

		return nil, requestErr
	}

	request.URL.RawQuery = query.Encode()

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		cancel()

		return nil, requestErr
	}

	apiResponse, responseErr := readAPIResponse(operation, response, c.maxResponseBytes)

	cancel()

	if responseErr != nil {
		return nil, responseErr
	}

	return apiResponse, nil
}

// queryLogFromWire converts a decoded query-log response.
//
// Parameters:
//   - wire: The decoded query-log response.
//
// Returns:
//   - log: The public query-log page when every entry is valid.
//   - err: A response-contract error; otherwise nil.
func queryLogFromWire(wire queryLogResponse) (*QueryLog, error) {
	log := &QueryLog{Oldest: wire.Oldest}
	if wire.Data == nil {
		return log, nil
	}

	data := make([]QueryLogEntry, 0, len(*wire.Data))
	for index, wireEntry := range *wire.Data {
		if wireEntry == nil {
			return nil, fmt.Errorf("data[%d]: %w", index, errRequiredQueryLogField)
		}

		entry, err := queryLogEntryFromWire(*wireEntry)
		if err != nil {
			return nil, fmt.Errorf("data[%d]: %w", index, err)
		}

		data = append(data, *entry)
	}

	log.Data = &data

	return log, nil
}

// queryLogEntryFromWire converts one decoded query-log entry.
//
// Parameters:
//   - wire: The decoded query-log entry.
//
// Returns:
//   - entry: The public query-log entry when the entry is valid.
//   - err: A response-contract error; otherwise nil.
func queryLogEntryFromWire(wire queryLogEntryResponse) (*QueryLogEntry, error) {
	err := validateQueryLogEntry(wire)
	if err != nil {
		return nil, fmt.Errorf("validate entry: %w", err)
	}

	entry := &QueryLogEntry{
		Answer:         wire.Answer,
		OriginalAnswer: wire.OriginalAnswer,
		Cached:         wire.Cached,
		Upstream:       wire.Upstream,
		AnswerDNSSEC:   wire.AnswerDNSSEC,
		Client:         wire.Client,
		ClientID:       wire.ClientID,
		ClientProtocol: wire.ClientProtocol,
		ECS:            wire.ECS,
		ElapsedMS:      wire.ElapsedMS,
		Question:       wire.Question,
		FilterID:       wire.FilterID,
		Rule:           wire.Rule,
		Rules:          wire.Rules,
		Reason:         wire.Reason,
		ServiceName:    wire.ServiceName,
		Status:         wire.Status,
		Time:           wire.Time,
	}

	if wire.ClientInfo != nil {
		clientInfo, err := queryLogClientFromWire(*wire.ClientInfo)
		if err != nil {
			return nil, fmt.Errorf("client_info: %w", err)
		}

		entry.ClientInfo = clientInfo
	}

	return entry, nil
}

// validateQueryLogEntry checks the response contract of one query-log entry.
//
// Parameters:
//   - wire: The decoded query-log entry to validate.
//
// Returns:
//   - err: An invalid-reason or missing-required-field error; otherwise nil.
func validateQueryLogEntry(wire queryLogEntryResponse) error {
	if wire.Reason != nil && !validFilteringReason(*wire.Reason) {
		return fmt.Errorf("reason: %w", errInvalidQueryLogReason)
	}
	if wire.Rules == nil {
		return nil
	}

	for index, rule := range *wire.Rules {
		if rule == nil {
			return fmt.Errorf("rules[%d]: %w", index, errRequiredQueryLogField)
		}
	}

	return nil
}

// queryLogClientFromWire converts decoded query-log client details.
//
// Parameters:
//   - wire: The decoded client details.
//
// Returns:
//   - client: The public client details when every required member is present.
//   - err: A missing-required-field error; otherwise nil.
func queryLogClientFromWire(wire queryLogClientResponse) (*QueryLogClient, error) {
	switch {
	case wire.Disallowed == nil:
		return nil, fmt.Errorf("disallowed: %w", errRequiredQueryLogField)
	case wire.DisallowedRule == nil:
		return nil, fmt.Errorf("disallowed_rule: %w", errRequiredQueryLogField)
	case wire.Name == nil:
		return nil, fmt.Errorf("name: %w", errRequiredQueryLogField)
	case wire.Whois == nil:
		return nil, fmt.Errorf("whois: %w", errRequiredQueryLogField)
	default:
	}

	return &QueryLogClient{
		Disallowed:     *wire.Disallowed,
		DisallowedRule: *wire.DisallowedRule,
		Name:           *wire.Name,
		Whois:          wire.Whois,
	}, nil
}

// queryLogConfigFromWire converts a decoded query-log configuration.
//
// Parameters:
//   - wire: The decoded query-log configuration.
//
// Returns:
//   - config: The public configuration when every required member is present.
//   - err: A missing-required-field error; otherwise nil.
func queryLogConfigFromWire(wire queryLogConfigResponse) (*QueryLogConfig, error) {
	switch {
	case wire.Enabled == nil:
		return nil, fmt.Errorf("enabled: %w", errRequiredQueryLogField)
	case wire.Interval == nil:
		return nil, fmt.Errorf("interval: %w", errRequiredQueryLogField)
	case wire.AnonymizeClientIP == nil:
		return nil, fmt.Errorf("anonymize_client_ip: %w", errRequiredQueryLogField)
	case wire.Ignored == nil:
		return nil, fmt.Errorf("ignored: %w", errRequiredQueryLogField)
	default:
	}

	return &QueryLogConfig{
		Enabled:           *wire.Enabled,
		Interval:          *wire.Interval,
		AnonymizeClientIP: *wire.AnonymizeClientIP,
		Ignored:           *wire.Ignored,
		IgnoredEnabled:    wire.IgnoredEnabled,
	}, nil
}

// queryLogRequestError creates a structured query-log request error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The request-construction cause.
//
// Returns:
//   - The structured request error.
func queryLogRequestError(operation, method string, cause error) *Error {
	requestErr := newError(ErrorKindRequest)

	requestErr.Operation = operation
	requestErr.Method = method
	requestErr.Err = cause

	return requestErr
}

// queryLogJSONError creates a structured query-log JSON error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - cause: The decoding or response-contract cause.
//
// Returns:
//   - The structured JSON error, which always reports GET.
func queryLogJSONError(operation string, cause error) *Error {
	requestErr := newError(ErrorKindJSON)

	requestErr.Operation = operation
	requestErr.Method = http.MethodGet
	requestErr.Err = cause

	return requestErr
}
