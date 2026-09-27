// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// FilteringService exposes filtering status, configuration, subscriptions, custom
// rules, and host evaluation.
type FilteringService interface {
	FilteringStatus(ctx context.Context) (*FilteringStatus, error)
	UpdateFilteringConfig(ctx context.Context, config FilteringConfig) error
	AddFilteringURL(ctx context.Context, request AddFilteringURLRequest) error
	RemoveFilteringURL(ctx context.Context, request RemoveFilteringURLRequest) error
	SetFilteringURL(ctx context.Context, request *SetFilteringURLRequest) error
	RefreshFiltering(
		ctx context.Context,
		request *RefreshFilteringRequest,
	) (*FilteringRefreshResult, error)
	SetFilteringRules(ctx context.Context, request *SetFilteringRulesRequest) error
	CheckFilteredHost(ctx context.Context, request CheckHostRequest) (*FilteredHostResult, error)
}

// FilterSubscription describes one filtering-rule subscription returned by
// AdGuard Home.
//
// Enabled, ID, Name, RulesCount, and URL are required. A missing or null
// required field causes FilteringStatus to return a JSON error. LastUpdated is
// optional; nil represents an absent or null value.
type FilterSubscription struct {
	// Enabled reports whether the subscription is enabled.
	Enabled bool
	// ID is the subscription identifier.
	ID int64
	// LastUpdated is the subscription's most recent update time, or nil when
	// the server omitted it or returned null.
	LastUpdated *time.Time
	// Name is the subscription display name.
	Name string
	// RulesCount is the number of rules in the subscription.
	RulesCount uint32
	// URL is the subscription location.
	URL string
}

// FilteringStatus is the response-only filtering configuration snapshot.
//
// Every field is optional. A nil field represents an absent or null response
// value, while a pointer to false, zero, or an empty slice preserves an
// explicitly reported value. Subscription entries are required to contain
// Enabled, ID, Name, RulesCount, and URL.
type FilteringStatus struct {
	// Enabled is the optional filtering service state.
	Enabled *bool
	// Interval is the optional automatic filter refresh interval.
	Interval *int64
	// Filters contains the optional filtering subscription list. Nil means
	// absent or null; a pointer to an empty slice means an explicitly empty list.
	Filters *[]FilterSubscription
	// WhitelistFilters contains the optional allowlist subscription list. Nil
	// means absent or null; a pointer to an empty slice means an empty list.
	WhitelistFilters *[]FilterSubscription
	// UserRules contains the optional custom filtering rule list. Nil means
	// absent or null; a pointer to an empty slice means an empty list.
	UserRules *[]string
}

// FilteringConfig updates the general filtering configuration.
//
// A nil field is omitted from the JSON object, while a nonnil field preserves
// explicit false or zero values.
type FilteringConfig struct {
	// Enabled controls whether filtering is enabled. Nil omits the field.
	Enabled *bool `json:"enabled,omitempty"`
	// Interval controls the automatic filter refresh interval. Nil omits the
	// field.
	Interval *int64 `json:"interval,omitempty"`
}

// AddFilteringURLRequest adds a filter subscription.
//
// Nil fields are omitted from the JSON object, while nonnil fields preserve
// explicit empty-string and false values.
type AddFilteringURLRequest struct {
	// Name is the optional subscription display name. Nil omits the field.
	Name *string `json:"name,omitzero"`
	// URL is the optional filter URL or absolute file path. Nil omits the field.
	URL *string `json:"url,omitzero"`
	// Whitelist optionally selects allowlist mode. Nil omits the field; a pointer
	// to false explicitly requests a filtering list.
	Whitelist *bool `json:"whitelist,omitempty"`
}

// RemoveFilteringURLRequest removes a filter subscription.
//
// Nil fields are omitted from the JSON object, while nonnil fields preserve
// explicit empty-string and false values.
type RemoveFilteringURLRequest struct {
	// URL is the optional previously added filter URL or absolute file path.
	// Nil omits the field.
	URL *string `json:"url,omitzero"`
	// Whitelist optionally identifies an allowlist subscription. Nil omits the
	// field; a pointer to false explicitly identifies a filtering list.
	Whitelist *bool `json:"whitelist,omitempty"`
}

// FilteringURLData contains the required replacement values for one filtering
// subscription.
//
// All fields are always serialized, including false, the empty string, and
// zero values where applicable.
type FilteringURLData struct {
	// Enabled reports whether the replacement subscription is enabled.
	Enabled bool `json:"enabled"`
	// Name is the replacement subscription display name.
	Name string `json:"name"`
	// URL is the replacement subscription location.
	URL string `json:"url"`
}

// SetFilteringURLRequest updates a filter subscription.
//
// A nil request causes SetFilteringURL to omit the body. A nonnil request is
// encoded as an object and must contain Data. Other nil fields are omitted,
// while nonnil fields preserve explicit empty-string and false values.
type SetFilteringURLRequest struct {
	// Data contains the required replacement subscription data. A nonnil
	// request with nil Data is rejected before transport.
	Data *FilteringURLData `json:"data,omitempty"`
	// URL optionally identifies the subscription to update. Nil omits the field.
	URL *string `json:"url,omitzero"`
	// Whitelist optionally identifies an allowlist subscription. Nil omits the
	// field; a pointer to false explicitly identifies a filtering list.
	Whitelist *bool `json:"whitelist,omitempty"`
}

// RefreshFilteringRequest selects which subscription class to refresh.
//
// A nil request causes RefreshFiltering to omit the body. A nonnil request is
// encoded as an object, even when every field is nil.
type RefreshFilteringRequest struct {
	// Whitelist selects allowlists when true and filtering lists when false or
	// absent. Nil omits the field; a pointer to false preserves false.
	Whitelist *bool `json:"whitelist,omitempty"`
}

// FilteringRefreshResult is the response-only filtering refresh result.
//
// Updated is optional; nil represents an absent or null response value.
type FilteringRefreshResult struct {
	// Updated is the optional number of subscriptions updated by the refresh.
	Updated *int64
}

// SetFilteringRulesRequest replaces the custom filtering rules.
//
// A nil request causes SetFilteringRules to omit the body. A nonnil request is
// encoded as an object even when Rules is nil.
type SetFilteringRulesRequest struct {
	// Rules contains the replacement rules. Nil omits the rules property, while
	// a nonnil empty slice is serialized as an empty array that clears the rules.
	Rules *[]string `json:"rules,omitzero"`
}

// CheckHostRequest identifies the host to check through query parameters.
//
// Name is always encoded as the name query parameter. Nil Client and QType
// fields are omitted; nonnil values are encoded even when empty.
type CheckHostRequest struct {
	// Name is the required host name encoded as the name query parameter.
	Name string `json:"-"`
	// Client is the optional client identifier or IP address. Nil omits the
	// client query parameter.
	Client *string `json:"-"`
	// QType is the optional DNS query type. Nil omits the qtype query parameter.
	QType *string `json:"-"`
}

// FilteringRule describes one optional rule entry returned by a host check.
//
// Both fields are optional; nil represents an absent or null response value.
type FilteringRule struct {
	// FilterListID is the optional subscription identifier containing the rule.
	FilterListID *int64
	// Text is the optional rule text.
	Text *string
}

// FilteredHostResult is the response-only result of a filtering host check.
//
// Every field is optional. A nil field represents an absent or null response
// value, while a pointer to an empty slice preserves an explicitly empty list.
// When Reason is present, it must be a documented FilteringReason value.
type FilteredHostResult struct {
	// Reason is the optional filtering outcome. A present value must be
	// documented by this package.
	Reason *FilteringReason
	// FilterID is the optional legacy subscription identifier.
	FilterID *int64
	// Rule is the optional legacy applied rule text.
	Rule *string
	// Rules contains the optional applied rule list. Nil means absent or null;
	// a pointer to an empty slice means an explicitly empty list.
	Rules *[]FilteringRule
	// ServiceName is the optional blocked service name.
	ServiceName *string
	// CNAME is the optional rewrite canonical name.
	CNAME *string
	// IPAddresses contains the optional rewrite address list. Nil means absent
	// or null; a pointer to an empty slice means an explicitly empty list.
	IPAddresses *[]string
}

// FilteringReason identifies a filtering outcome returned by a host check.
//
// The client accepts only the FilteringReason values declared in this file.
// FilteringReasonNotFilteredError is a successful HTTP result representing a
// filtering evaluation failure, not a transport or client error.
type FilteringReason string

// filteringSubscriptionResponse preserves required and optional filtering
// subscription response fields before conversion to FilterSubscription.
type filteringSubscriptionResponse struct {
	// Enabled is nil when the required field is absent or null.
	Enabled *bool `json:"enabled"`
	// ID is nil when the required field is absent or null.
	ID *int64 `json:"id"`
	// LastUpdated is nil when the optional field is absent or null.
	LastUpdated *time.Time `json:"last_updated"`
	// Name is nil when the required field is absent or null.
	Name *string `json:"name"`
	// RulesCount is nil when the required field is absent or null.
	RulesCount *uint32 `json:"rules_count"`
	// URL is nil when the required field is absent or null.
	URL *string `json:"url"`
}

// filteringStatusResponse preserves optional filtering status response values.
type filteringStatusResponse struct {
	// Enabled is nil when the field is absent or null.
	Enabled *bool `json:"enabled"`
	// Interval is nil when the field is absent or null.
	Interval *int64 `json:"interval"`
	// Filters is nil when the field is absent or null.
	Filters *[]filteringSubscriptionResponse `json:"filters"`
	// WhitelistFilters is nil when the field is absent or null.
	WhitelistFilters *[]filteringSubscriptionResponse `json:"whitelist_filters"`
	// UserRules is nil when the field is absent or null.
	UserRules *[]string `json:"user_rules"`
}

// filteringRefreshResponse preserves the optional refresh count.
type filteringRefreshResponse struct {
	// Updated is nil when the field is absent or null.
	Updated *int64 `json:"updated"`
}

// filteringRuleResponse preserves optional host-check rule fields.
type filteringRuleResponse struct {
	// FilterListID is nil when the field is absent or null.
	FilterListID *int64 `json:"filter_list_id"`
	// Text is nil when the field is absent or null.
	Text *string `json:"text"`
}

// filteredHostResponse preserves optional filtering host-check response fields.
type filteredHostResponse struct {
	// Reason is nil when the field is absent or null.
	Reason *FilteringReason `json:"reason"`
	// FilterID is nil when the field is absent or null.
	FilterID *int64 `json:"filter_id"`
	// Rule is nil when the field is absent or null.
	Rule *string `json:"rule"`
	// Rules is nil when the field is absent or null.
	Rules *[]filteringRuleResponse `json:"rules"`
	// ServiceName is nil when the field is absent or null.
	ServiceName *string `json:"service_name"`
	// CNAME is nil when the field is absent or null.
	CNAME *string `json:"cname"`
	// IPAddresses is nil when the field is absent or null.
	IPAddresses *[]string `json:"ip_addrs"`
}

const (
	// FilteringReasonNotFilteredNotFound indicates that no matching rule was found.
	FilteringReasonNotFilteredNotFound FilteringReason = "NotFilteredNotFound"
	// FilteringReasonNotFilteredWhiteList indicates that an allowlist matched.
	FilteringReasonNotFilteredWhiteList FilteringReason = "NotFilteredWhiteList"
	// FilteringReasonNotFilteredError indicates that filtering could not be evaluated.
	FilteringReasonNotFilteredError FilteringReason = "NotFilteredError"
	// FilteringReasonFilteredBlackList indicates that a filtering rule matched.
	FilteringReasonFilteredBlackList FilteringReason = "FilteredBlackList"
	// FilteringReasonFilteredSafeBrowsing indicates that safe browsing blocked the host.
	FilteringReasonFilteredSafeBrowsing FilteringReason = "FilteredSafeBrowsing"
	// FilteringReasonFilteredParental indicates that parental filtering blocked the host.
	FilteringReasonFilteredParental FilteringReason = "FilteredParental"
	// FilteringReasonFilteredInvalid indicates that the host was invalid.
	FilteringReasonFilteredInvalid FilteringReason = "FilteredInvalid"
	// FilteringReasonFilteredSafeSearch indicates that safe search filtering matched.
	FilteringReasonFilteredSafeSearch FilteringReason = "FilteredSafeSearch"
	// FilteringReasonFilteredBlockedService indicates that a blocked service matched.
	FilteringReasonFilteredBlockedService FilteringReason = "FilteredBlockedService"
	// FilteringReasonRewrite indicates that a rewrite rule matched.
	FilteringReasonRewrite FilteringReason = "Rewrite"
	// FilteringReasonRewriteEtcHosts indicates that an etc-hosts rewrite matched.
	FilteringReasonRewriteEtcHosts FilteringReason = "RewriteEtcHosts"
	// FilteringReasonRewriteRule indicates that a rewrite rule expression matched.
	FilteringReasonRewriteRule FilteringReason = "RewriteRule"
)

const (
	// FilteringStatusOperation identifies FilteringStatus errors.
	filteringStatusOperation = "filtering_status"
	// FilteringConfigOperation identifies filtering configuration errors.
	filteringConfigOperation = "filtering_config"
	// FilteringAddURLOperation identifies AddFilteringURL errors.
	filteringAddURLOperation = "filtering_add_url"
	// FilteringRemoveURLOperation identifies RemoveFilteringURL errors.
	filteringRemoveURLOperation = "filtering_remove_url"
	// FilteringSetURLOperation identifies SetFilteringURL errors.
	filteringSetURLOperation = "filtering_set_url"
	// FilteringRefreshOperation identifies RefreshFiltering errors.
	filteringRefreshOperation = "filtering_refresh"
	// FilteringSetRulesOperation identifies SetFilteringRules errors.
	filteringSetRulesOperation = "filtering_set_rules"
	// FilteringCheckHostOperation identifies CheckFilteredHost errors.
	filteringCheckHostOperation = "filtering_check_host"
	// FilteringSubscriptionEndpoint is the filtering status endpoint.
	filteringSubscriptionEndpoint = "control/filtering/status"
)

var (
	// ErrRequiredFilteringSubscriptionField identifies an absent or null
	// required subscription field.
	errRequiredFilteringSubscriptionField = errors.New("required filtering subscription field is missing")
	// ErrInvalidFilteringReason identifies a filtering reason outside the
	// documented response contract.
	errInvalidFilteringReason = errors.New("invalid filtering reason")
	// ErrNullJSONResponse identifies a top-level null JSON object response.
	errNullJSONResponse = errors.New("response must be a JSON object")
)

var _ FilteringService = (*Client)(nil)

// FilteringStatus retrieves the current filtering configuration.
//
// The successful response must be a JSON object with a JSON media type. Every
// top-level field is optional, and each subscription must contain all required
// fields except LastUpdated.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - status: The decoded filtering configuration when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, JSON, or required-field failures; otherwise nil.
func (c *Client) FilteringStatus(ctx context.Context) (*FilteringStatus, error) {
	response, requestErr := c.get(ctx, filteringStatusOperation, filteringSubscriptionEndpoint)
	if requestErr != nil {
		return nil, requestErr
	}

	status, decodeErr := decodeFilteringStatus(response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return status, nil
}

// UpdateFilteringConfig updates the general filtering configuration.
//
// The config value is always encoded as a JSON object. Nil fields are omitted,
// while nonnil fields preserve explicit false and zero values. Any 2xx response
// is accepted without interpreting its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The filtering settings to update.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or response-body
//     failures; otherwise nil.
func (c *Client) UpdateFilteringConfig(
	ctx context.Context,
	config FilteringConfig,
) error {
	requestErr := c.doFilteringNoContent(
		ctx,
		filteringConfigOperation,
		"control/filtering/config",
		config,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// AddFilteringURL adds a filter subscription.
//
// The request value is always encoded as a JSON object. Nil fields are omitted,
// while nonnil fields preserve explicit empty-string and false values. Any 2xx
// response is accepted without interpreting its body, but the response is still
// bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The subscription values to add.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or response-body
//     failures; otherwise nil.
func (c *Client) AddFilteringURL(ctx context.Context, request AddFilteringURLRequest) error {
	requestErr := c.doFilteringNoContent(
		ctx,
		filteringAddURLOperation,
		"control/filtering/add_url",
		request,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// RemoveFilteringURL removes a filter subscription.
//
// The request value is always encoded as a JSON object. Nil fields are omitted,
// while nonnil fields preserve explicit empty-string and false values. Any 2xx
// response is accepted without interpreting its body, but the response is still
// bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The subscription identifier to remove.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or response-body
//     failures; otherwise nil.
func (c *Client) RemoveFilteringURL(ctx context.Context, request RemoveFilteringURLRequest) error {
	requestErr := c.doFilteringNoContent(
		ctx,
		filteringRemoveURLOperation,
		"control/filtering/remove_url",
		request,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// SetFilteringURL updates a filter subscription.
//
// A nil request omits the body. A nonnil request is encoded as an object and
// must contain Data; a missing Data value is rejected before transport. Other
// nil fields are omitted, while nonnil fields preserve explicit empty-string and
// false values. Any 2xx response is accepted without interpreting its body, but
// the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional update body. A nonnil value must contain Data.
//
// Returns:
//   - err: An *Error for a missing required field, request, redirect, HTTP,
//     response-limit, or response-body failure; otherwise nil.
func (c *Client) SetFilteringURL(ctx context.Context, request *SetFilteringURLRequest) error {
	var body any

	if request != nil {
		if request.Data == nil {
			return filteringRequestError(
				filteringSetURLOperation,
				http.MethodPost,
				errRequiredFilteringSubscriptionField,
			)
		}

		body = request
	}

	requestErr := c.doFilteringNoContent(
		ctx,
		filteringSetURLOperation,
		"control/filtering/set_url",
		body,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// RefreshFiltering reloads filtering subscriptions.
//
// A nil request omits the body. A nonnil request is encoded as an object, even
// when Whitelist is nil. The successful response must be a JSON object with a
// JSON media type; Updated may be absent or null.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional subscription-class selector.
//
// Returns:
//   - result: The decoded filtering refresh result.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, or JSON failures; otherwise nil.
func (c *Client) RefreshFiltering(
	ctx context.Context,
	request *RefreshFilteringRequest,
) (*FilteringRefreshResult, error) {
	var body any

	if request != nil {
		body = request
	}

	response, requestErr := c.doFilteringJSON(
		ctx,
		filteringRefreshOperation,
		http.MethodPost,
		"control/filtering/refresh",
		body,
		nil,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var wireResult filteringRefreshResponse

	err := unmarshalFilteringObject(response.body, &wireResult)
	if err != nil {
		return nil, filteringJSONError(filteringRefreshOperation, http.MethodPost, err)
	}

	return &FilteringRefreshResult{Updated: wireResult.Updated}, nil
}

// SetFilteringRules replaces the custom filtering rules.
//
// A nil request omits the body. A nonnil request is encoded as an object even
// when Rules is nil. A nonnil empty Rules slice is encoded as an empty array to
// clear the rules. Any 2xx response is accepted without interpreting its body,
// but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional replacement rules body.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or response-body
//     failures; otherwise nil.
func (c *Client) SetFilteringRules(ctx context.Context, request *SetFilteringRulesRequest) error {
	var body any

	if request != nil {
		body = request
	}

	requestErr := c.doFilteringNoContent(
		ctx,
		filteringSetRulesOperation,
		"control/filtering/set_rules",
		body,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// CheckFilteredHost checks whether a host is filtered.
//
// Name is always encoded as the name query parameter. Nil Client and QType
// fields are omitted, while nonnil values are encoded even when empty. The
// successful response must be a JSON object with a JSON media type. Its fields
// are optional, and a present Reason must be a documented FilteringReason.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The host, optional client, and optional query type.
//
// Returns:
//   - result: The decoded filtering host-check result.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, JSON, or invalid-reason failures; otherwise nil.
func (c *Client) CheckFilteredHost(
	ctx context.Context,
	request CheckHostRequest,
) (*FilteredHostResult, error) {
	query := url.Values{"name": {request.Name}}
	if request.Client != nil {
		query.Set("client", *request.Client)
	}
	if request.QType != nil {
		query.Set("qtype", *request.QType)
	}

	response, requestErr := c.doFilteringJSON(
		ctx,
		filteringCheckHostOperation,
		http.MethodGet,
		"control/filtering/check_host",
		nil,
		query,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	result, decodeErr := decodeFilteredHostResult(response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return result, nil
}

// doFilteringJSON executes a filtering request that requires a successful JSON
// response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - method: The HTTP method used by the request and placed on errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - body: The optional request value. Nil omits the request body.
//   - query: The optional query parameters.
//
// Returns:
//   - response: The bounded successful JSON response body.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     or media-type failures; otherwise nil.
func (c *Client) doFilteringJSON(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	body any,
	query url.Values,
) (*apiResponse, *Error) {
	response, cancel, requestErr := c.doFiltering(
		ctx,
		operation,
		method,
		endpoint,
		body,
		query,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	apiResponse, responseErr := readAPIResponse(operation, response, c.maxResponseBytes)

	cancel()

	if responseErr != nil {
		responseErr.Method = method

		return nil, responseErr
	}

	return apiResponse, nil
}

// doFilteringNoContent executes a filtering POST whose successful body is not
// interpreted.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - body: The optional request value. Nil omits the request body.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) doFilteringNoContent(
	ctx context.Context,
	operation string,
	endpoint string,
	body any,
) *Error {
	response, cancel, requestErr := c.doFiltering(
		ctx,
		operation,
		http.MethodPost,
		endpoint,
		body,
		nil,
	)
	if requestErr != nil {
		return requestErr
	}

	responseErr := readFilteringNoContent(operation, response, c.maxResponseBytes)

	cancel()

	if responseErr != nil {
		responseErr.Method = http.MethodPost
	}

	return responseErr
}

// doFiltering creates and executes a bounded-timeout filtering request.
//
// A nil body omits the request bytes. A nonnil body is JSON encoded. POST
// requests set a JSON content type even when body is nil. The caller must call
// the returned cancel function after consuming the response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - method: The HTTP method used by the request and placed on errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - body: The optional request value to JSON encode.
//   - query: The optional query parameters.
//
// Returns:
//   - response: The HTTP response when transport succeeds.
//   - cancel: The function that releases the request context.
//   - err: An *Error for body-encoding, request-creation, transport, context, or
//     redirect failures; otherwise nil.
func (c *Client) doFiltering(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	body any,
	query url.Values,
) (*http.Response, context.CancelFunc, *Error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	reader, encodeErr := filteringRequestReader(body)
	if encodeErr != nil {
		cancel()

		return nil, nil, filteringRequestError(
			operation,
			method,
			fmt.Errorf("encode request body: %w", encodeErr),
		)
	}

	requestURL := c.endpoint(endpoint)
	if query != nil {
		requestURL.RawQuery = query.Encode()
	}

	request, err := http.NewRequestWithContext(requestContext, method, requestURL.String(), reader)
	if err != nil {
		cancel()

		return nil, nil, filteringRequestError(operation, method, fmt.Errorf("%w: %w", errCreateRequest, err))
	}

	request.Header.Set("Accept", jsonContentType)
	request.Header.Set("User-Agent", c.userAgent)

	if method == http.MethodPost {
		request.Header.Set("Content-Type", jsonContentType)
	}
	if c.basicAuth {
		request.SetBasicAuth(c.username, c.password)
	}

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		cancel()

		requestErr.Method = method

		return nil, nil, requestErr
	}

	return response, cancel, nil
}

// filteringRequestReader encodes an optional filtering request body.
//
// A nil body produces an empty request body. A nonnil body is JSON encoded.
//
// Parameters:
//   - body: The optional request value to JSON encode.
//
// Returns:
//   - reader: The request body reader, or an empty body when body is nil.
//   - err: The JSON encoding error when body cannot be encoded; otherwise nil.
func filteringRequestReader(body any) (io.Reader, error) {
	if body == nil {
		return http.NoBody, nil
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return bytes.NewReader(encoded), nil
}

// readFilteringNoContent reads, bounds, and closes a filtering mutation response
// before status validation.
//
// Any 2xx response is accepted regardless of media type or body content. The
// body is consumed only to enforce the configured limit and populate status
// errors.
//
// Parameters:
//   - operation: The operation name placed on structured errors.
//   - response: The HTTP response to consume and validate.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - err: An *Error for response-limit, response-body, or HTTP-status failures;
//     otherwise nil.
func readFilteringNoContent(operation string, response *http.Response, limit int64) *Error {
	body, tooLarge, readErr := readBounded(response.Body, limit)
	closeErr := response.Body.Close()

	switch {
	case tooLarge:
		clientErr := responseError(operation, ErrorKindResponseTooLarge, response, nil)

		clientErr.Method = http.MethodPost
		clientErr.Limit = limit

		return clientErr
	case readErr != nil:
		clientErr := responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errReadResponse, readErr),
		)

		clientErr.Method = http.MethodPost

		return clientErr
	case closeErr != nil:
		clientErr := responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errCloseResponse, closeErr),
		)

		clientErr.Method = http.MethodPost

		return clientErr
	case response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices:
		clientErr := statusError(
			operation,
			http.MethodPost,
			response.StatusCode,
			response.Status,
			response.Header.Get("Content-Type"),
			body,
		)

		return clientErr
	default:
		return nil
	}
}

// decodeFilteringStatus decodes and validates a filtering status object.
//
// A top-level null is rejected. Optional top-level fields preserve presence,
// and every subscription must contain all required fields except LastUpdated.
//
// Parameters:
//   - body: The bounded JSON response body.
//
// Returns:
//   - status: The decoded filtering status when the response is valid.
//   - err: A JSON-kind *Error for null, malformed, or required-field failures;
//     otherwise nil.
func decodeFilteringStatus(body []byte) (*FilteringStatus, *Error) {
	var wireStatus filteringStatusResponse

	err := unmarshalFilteringObject(body, &wireStatus)
	if err != nil {
		return nil, filteringJSONError(filteringStatusOperation, http.MethodGet, err)
	}

	status := &FilteringStatus{
		Enabled:          wireStatus.Enabled,
		Interval:         wireStatus.Interval,
		Filters:          nil,
		WhitelistFilters: nil,
		UserRules:        wireStatus.UserRules,
	}
	if wireStatus.Filters != nil {
		filters, convertErr := convertFilteringSubscriptions(*wireStatus.Filters)
		if convertErr != nil {
			return nil, filteringJSONError(filteringStatusOperation, http.MethodGet, convertErr)
		}

		status.Filters = &filters
	}
	if wireStatus.WhitelistFilters != nil {
		filters, convertErr := convertFilteringSubscriptions(*wireStatus.WhitelistFilters)
		if convertErr != nil {
			return nil, filteringJSONError(filteringStatusOperation, http.MethodGet, convertErr)
		}

		status.WhitelistFilters = &filters
	}

	return status, nil
}

// convertFilteringSubscriptions validates wire subscriptions and converts them
// to public models.
//
// Parameters:
//   - wireFilters: The decoded subscription entries to validate and convert.
//
// Returns:
//   - filters: The converted subscriptions when every entry is valid.
//   - err: An error identifying the first invalid subscription or required field;
//     otherwise nil.
func convertFilteringSubscriptions(
	wireFilters []filteringSubscriptionResponse,
) ([]FilterSubscription, error) {
	filters := make([]FilterSubscription, 0, len(wireFilters))
	for index := range wireFilters {
		wireFilter := wireFilters[index]
		err := validateFilteringSubscription(wireFilter)
		if err != nil {
			return nil, fmt.Errorf("filters[%d]: %w", index, err)
		}

		filters = append(filters, FilterSubscription{
			Enabled:     *wireFilter.Enabled,
			ID:          *wireFilter.ID,
			LastUpdated: wireFilter.LastUpdated,
			Name:        *wireFilter.Name,
			RulesCount:  *wireFilter.RulesCount,
			URL:         *wireFilter.URL,
		})
	}

	return filters, nil
}

// validateFilteringSubscription validates required wire subscription fields.
//
// LastUpdated is intentionally optional because the response contract does not
// require it.
//
// Parameters:
//   - filter: The decoded subscription entry to validate.
//
// Returns:
//   - err: An error identifying the first missing or null required field;
//     otherwise nil.
func validateFilteringSubscription(filter filteringSubscriptionResponse) error {
	requiredFields := []struct {
		name  string
		value bool
	}{
		{name: "enabled", value: filter.Enabled != nil},
		{name: "id", value: filter.ID != nil},
		{name: "name", value: filter.Name != nil},
		{name: "rules_count", value: filter.RulesCount != nil},
		{name: "url", value: filter.URL != nil},
	}
	for _, field := range requiredFields {
		if !field.value {
			return fmt.Errorf("%s: %w", field.name, errRequiredFilteringSubscriptionField)
		}
	}

	return nil
}

// decodeFilteredHostResult decodes and validates a filtering host-check object.
//
// A top-level null is rejected. Response fields are optional, but a present
// Reason must be one of the documented FilteringReason values.
//
// Parameters:
//   - body: The bounded JSON response body.
//
// Returns:
//   - result: The decoded host-check result when the response is valid.
//   - err: A JSON-kind *Error for null, malformed, or invalid-reason failures;
//     otherwise nil.
func decodeFilteredHostResult(body []byte) (*FilteredHostResult, *Error) {
	var wireResult filteredHostResponse

	err := unmarshalFilteringObject(body, &wireResult)
	if err != nil {
		return nil, filteringJSONError(filteringCheckHostOperation, http.MethodGet, err)
	}
	if wireResult.Reason != nil && !validFilteringReason(*wireResult.Reason) {
		return nil, filteringJSONError(
			filteringCheckHostOperation,
			http.MethodGet,
			errInvalidFilteringReason,
		)
	}

	result := &FilteredHostResult{
		Reason:      wireResult.Reason,
		FilterID:    wireResult.FilterID,
		Rule:        wireResult.Rule,
		Rules:       nil,
		ServiceName: wireResult.ServiceName,
		CNAME:       wireResult.CNAME,
		IPAddresses: wireResult.IPAddresses,
	}
	if wireResult.Rules != nil {
		rules := make([]FilteringRule, 0, len(*wireResult.Rules))
		for _, wireRule := range *wireResult.Rules {
			rules = append(rules, FilteringRule(wireRule))
		}

		result.Rules = &rules
	}

	return result, nil
}

// validFilteringReason reports whether reason is documented by this package.
//
// Parameters:
//   - reason: The filtering reason to validate.
//
// Returns:
//   - valid: Whether reason is a documented FilteringReason value.
func validFilteringReason(reason FilteringReason) bool {
	switch reason {
	case FilteringReasonNotFilteredNotFound,
		FilteringReasonNotFilteredWhiteList,
		FilteringReasonNotFilteredError,
		FilteringReasonFilteredBlackList,
		FilteringReasonFilteredSafeBrowsing,
		FilteringReasonFilteredParental,
		FilteringReasonFilteredInvalid,
		FilteringReasonFilteredSafeSearch,
		FilteringReasonFilteredBlockedService,
		FilteringReasonRewrite,
		FilteringReasonRewriteEtcHosts,
		FilteringReasonRewriteRule:
		return true
	default:
		return false
	}
}

// unmarshalFilteringObject strictly decodes a non-null JSON object into target.
//
// Parameters:
//   - body: The bounded JSON response body.
//   - target: The destination for the decoded object.
//
// Returns:
//   - err: An error identifying a top-level null or malformed JSON; otherwise nil.
func unmarshalFilteringObject(body []byte, target any) error {
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return errNullJSONResponse
	}

	err := json.Unmarshal(body, target)
	if err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	return nil
}

// filteringJSONError creates a structured filtering JSON decoding or validation
// error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The JSON decoding or validation cause.
//
// Returns:
//   - err: The structured JSON error.
func filteringJSONError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}

// filteringRequestError creates a structured filtering request error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The request construction, encoding, or validation cause.
//
// Returns:
//   - err: The structured request error.
func filteringRequestError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindRequest)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}
