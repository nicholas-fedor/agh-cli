// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
)

// RewriteService manages DNS rewrite rules and global rewrite settings.
type RewriteService interface {
	ListRewriteRules(ctx context.Context) ([]RewriteRule, error)
	AddRewriteRule(ctx context.Context, rule RewriteRule) error
	DeleteRewriteRule(ctx context.Context, rule RewriteRule) error
	UpdateRewriteRule(ctx context.Context, update RewriteUpdate) error
	GetRewriteSettings(ctx context.Context) (*RewriteSettings, error)
	UpdateRewriteSettings(ctx context.Context, settings RewriteSettings) error
}

// RewriteRule represents a DNS rewrite rule used in requests and responses.
//
// Nil fields are omitted from requests and represent absent or null response
// fields. A nonnil Enabled pointer preserves explicit false.
type RewriteRule struct {
	// Domain is the optional rewritten domain name.
	Domain *string
	// Answer is the optional A, AAAA, or CNAME answer.
	Answer *string
	// Enabled optionally controls whether the rule is active. Nil omits the
	// request field or represents an absent or null response value.
	Enabled *bool
}

// RewriteUpdate identifies a rewrite rule and its replacement values.
//
// Target and Update are always encoded as separate JSON objects. Nil fields
// within either object are omitted, while nonnil false and empty-string values
// are preserved.
type RewriteUpdate struct {
	// Target identifies the existing rule.
	Target RewriteRule
	// Update contains the replacement values.
	Update RewriteRule
}

// RewriteSettings contains the global DNS rewrite settings.
//
// The client requires the Enabled field in status responses and always
// serializes it in update requests, including false.
type RewriteSettings struct {
	// Enabled reports whether DNS rewrites are applied.
	Enabled bool
}

// rewriteRule preserves optional rewrite entry values on the wire.
type rewriteRule struct {
	// Domain is nil when the request or response field is omitted or null.
	Domain *string `json:"domain,omitempty"`
	// Answer is nil when the request or response field is omitted or null.
	Answer *string `json:"answer,omitempty"`
	// Enabled is nil when the request or response field is omitted or null.
	Enabled *bool `json:"enabled,omitempty"`
}

// rewriteUpdate preserves separate target and replacement request objects.
type rewriteUpdate struct {
	// Target identifies the existing rule.
	Target rewriteRule `json:"target"`
	// Update contains the replacement values.
	Update rewriteRule `json:"update"`
}

// rewriteSettings preserves the required enabled field on the wire.
type rewriteSettings struct {
	// Enabled is nil when a response field is absent or null. Update requests
	// always contain a nonnil value.
	Enabled *bool `json:"enabled"`
}

var (
	_ RewriteService = (*Client)(nil)
	// ErrInvalidRewriteList identifies a null or non-array rewrite list, or a
	// null list entry.
	errInvalidRewriteList = errors.New("rewrite list must be a JSON array of objects")
	// ErrInvalidRewriteSettings identifies an absent or null required enabled
	// field in a rewrite settings response.
	errInvalidRewriteSettings = errors.New("required rewrite settings field enabled is missing")
	// ErrEncodeRewriteRequest identifies a rewrite request encoding failure.
	errEncodeRewriteRequest = errors.New("encode rewrite request")
)

// ListRewriteRules retrieves the configured DNS rewrite rules.
//
// The successful response must use a JSON media type and contain a non-null
// array of non-null objects. Each rule field is optional; absent and null values
// decode to nil, while explicit false and empty-string values are preserved.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - rules: The decoded rewrite rules when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or list-contract failures; otherwise nil.
func (c *Client) ListRewriteRules(ctx context.Context) ([]RewriteRule, error) {
	operation := "list_rewrite_rules"
	response, requestErr := c.get(ctx, operation, "control/rewrite/list")
	if requestErr != nil {
		return nil, requestErr
	}

	rules, decodeErr := decodeRewriteRules(operation, response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return rules, nil
}

// AddRewriteRule adds a DNS rewrite rule.
//
// The rule is always encoded as a JSON object. Nil fields are omitted, while
// nonnil values preserve explicit false and empty-string values. Any 2xx
// response is accepted without interpreting its body, but the response is still
// bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - rule: The rewrite rule to add.
//
// Returns:
//   - err: An error wrapping a request, redirect, HTTP, response-limit,
//     response-body, or encoding failure; otherwise nil.
func (c *Client) AddRewriteRule(ctx context.Context, rule RewriteRule) error {
	operation := "add_rewrite_rule"
	payload := rewriteRule(rule)

	err := c.executeRewriteMutation(
		ctx,
		http.MethodPost,
		operation,
		"control/rewrite/add",
		payload,
	)
	if err != nil {
		return fmt.Errorf("execute add rewrite rule mutation: %w", err)
	}

	return nil
}

// DeleteRewriteRule deletes a DNS rewrite rule.
//
// The rule is always encoded as a JSON object. Nil fields are omitted, while
// nonnil values preserve explicit false and empty-string values. Any 2xx
// response is accepted without interpreting its body, but the response is still
// bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - rule: The rewrite rule identifying the entry to delete.
//
// Returns:
//   - err: An error wrapping a request, redirect, HTTP, response-limit,
//     response-body, or encoding failure; otherwise nil.
func (c *Client) DeleteRewriteRule(ctx context.Context, rule RewriteRule) error {
	operation := "delete_rewrite_rule"
	payload := rewriteRule(rule)

	err := c.executeRewriteMutation(
		ctx,
		http.MethodPost,
		operation,
		"control/rewrite/delete",
		payload,
	)
	if err != nil {
		return fmt.Errorf("execute delete rewrite rule mutation: %w", err)
	}

	return nil
}

// UpdateRewriteRule replaces an existing DNS rewrite rule.
//
// The target and replacement values are always encoded as separate nested JSON
// objects. Nil fields are omitted, while nonnil values preserve explicit false
// and empty-string values. Any 2xx response is accepted without interpreting
// its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - update: The existing rule identifier and replacement values.
//
// Returns:
//   - err: An error wrapping a request, redirect, HTTP, response-limit,
//     response-body, or encoding failure; otherwise nil.
func (c *Client) UpdateRewriteRule(ctx context.Context, update RewriteUpdate) error {
	operation := "update_rewrite_rule"
	payload := rewriteUpdate{
		Target: rewriteRule{
			Domain:  update.Target.Domain,
			Answer:  update.Target.Answer,
			Enabled: update.Target.Enabled,
		},
		Update: rewriteRule{
			Domain:  update.Update.Domain,
			Answer:  update.Update.Answer,
			Enabled: update.Update.Enabled,
		},
	}

	err := c.executeRewriteMutation(
		ctx,
		http.MethodPut,
		operation,
		"control/rewrite/update",
		payload,
	)
	if err != nil {
		return fmt.Errorf("execute rewrite rule update: %w", err)
	}

	return nil
}

// GetRewriteSettings retrieves the global DNS rewrite settings.
//
// The successful response must use a JSON media type and contain a non-null
// object with a present, non-null enabled field. Explicit false is preserved.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - settings: The decoded rewrite settings when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or missing enabled-field failures; otherwise nil.
func (c *Client) GetRewriteSettings(ctx context.Context) (*RewriteSettings, error) {
	operation := "get_rewrite_settings"
	response, requestErr := c.get(ctx, operation, "control/rewrite/settings")
	if requestErr != nil {
		return nil, requestErr
	}

	settings, decodeErr := decodeRewriteSettings(operation, response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return settings, nil
}

// UpdateRewriteSettings updates the global DNS rewrite settings.
//
// The required enabled value is always serialized, including false. Any 2xx
// response is accepted without interpreting its body, but the response is still
// bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - settings: The global rewrite settings to apply.
//
// Returns:
//   - err: An error wrapping a request, redirect, HTTP, response-limit,
//     response-body, or encoding failure; otherwise nil.
func (c *Client) UpdateRewriteSettings(ctx context.Context, settings RewriteSettings) error {
	operation := "update_rewrite_settings"
	payload := rewriteSettings{Enabled: &settings.Enabled}

	err := c.executeRewriteMutation(
		ctx,
		http.MethodPut,
		operation,
		"control/rewrite/settings/update",
		payload,
	)
	if err != nil {
		return fmt.Errorf("execute rewrite settings update: %w", err)
	}

	return nil
}

// decodeRewriteRules strictly decodes and validates a rewrite list response.
//
// Parameters:
//   - operation: The operation name placed on structured errors.
//   - body: The bounded JSON response body.
//
// Returns:
//   - rules: The decoded rewrite rules when the response is valid.
//   - err: A JSON-kind *Error for malformed JSON, a null list, or a null list
//     entry; otherwise nil.
func decodeRewriteRules(operation string, body []byte) ([]RewriteRule, *Error) {
	var wireRules *[]*rewriteRule

	err := json.Unmarshal(body, &wireRules)
	if err != nil {
		return nil, rewriteJSONError(operation, fmt.Errorf("decode response: %w", err))
	}
	if wireRules == nil {
		return nil, rewriteJSONError(operation, errInvalidRewriteList)
	}

	rules := make([]RewriteRule, 0, len(*wireRules))

	for _, wireRule := range *wireRules {
		if wireRule == nil {
			return nil, rewriteJSONError(operation, errInvalidRewriteList)
		}

		rules = append(rules, RewriteRule{
			Domain:  wireRule.Domain,
			Answer:  wireRule.Answer,
			Enabled: wireRule.Enabled,
		})
	}

	return rules, nil
}

// decodeRewriteSettings strictly decodes and validates a rewrite settings
// response.
//
// Parameters:
//   - operation: The operation name placed on structured errors.
//   - body: The bounded JSON response body.
//
// Returns:
//   - settings: The decoded settings when the required enabled field is present.
//   - err: A JSON-kind *Error for malformed JSON, a null object, or a missing
//     enabled field; otherwise nil.
func decodeRewriteSettings(operation string, body []byte) (*RewriteSettings, *Error) {
	var wireSettings *rewriteSettings

	err := json.Unmarshal(body, &wireSettings)
	if err != nil {
		return nil, rewriteJSONError(operation, fmt.Errorf("decode response: %w", err))
	}
	if wireSettings == nil || wireSettings.Enabled == nil {
		return nil, rewriteJSONError(operation, errInvalidRewriteSettings)
	}

	return &RewriteSettings{Enabled: *wireSettings.Enabled}, nil
}

// executeRewriteMutation sends a bodyless-success rewrite mutation.
//
// The request body is always JSON encoded. Any 2xx response is accepted
// without interpreting its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - method: The HTTP method used by the request and placed on errors.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - requestBody: The request value to JSON encode.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) executeRewriteMutation(
	ctx context.Context,
	method string,
	operation string,
	endpoint string,
	requestBody any,
) error {
	body, encodeErr := json.Marshal(requestBody)
	if encodeErr != nil {
		clientErr := newError(ErrorKindJSON)

		clientErr.Operation = operation
		clientErr.Method = method
		clientErr.Err = fmt.Errorf("%w: %w", errEncodeRewriteRequest, encodeErr)

		return clientErr
	}

	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newRewriteRequest(requestContext, method, operation, endpoint, body)
	if requestErr != nil {
		cancel()

		return requestErr
	}

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		requestErr.Method = method

		cancel()

		return requestErr
	}

	responseErr := readRewriteMutationResponse(operation, method, response, c.maxResponseBytes)

	cancel()

	if responseErr != nil {
		return responseErr
	}

	return nil
}

// newRewriteRequest creates an authenticated JSON rewrite request with the
// client's standard headers.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - method: The HTTP method used by the request and placed on errors.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - body: The already encoded JSON request body.
//
// Returns:
//   - request: The prepared HTTP request.
//   - err: A request-kind *Error when request construction fails; otherwise nil.
func (c *Client) newRewriteRequest(
	ctx context.Context,
	method string,
	operation string,
	endpoint string,
	body []byte,
) (*http.Request, *Error) {
	requestURL := c.endpoint(endpoint)
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), bytes.NewReader(body))
	if err != nil {
		clientErr := responseError(
			operation,
			ErrorKindRequest,
			nil,
			fmt.Errorf("%w: %w", errCreateRequest, err),
		)

		clientErr.Method = method

		return nil, clientErr
	}

	request.Header.Set("Accept", jsonContentType)
	request.Header.Set("Content-Type", jsonContentType)
	request.Header.Set("User-Agent", c.userAgent)

	if c.basicAuth {
		request.SetBasicAuth(c.username, c.password)
	}

	return request, nil
}

// readRewriteMutationResponse reads, bounds, and closes a rewrite mutation
// response before status validation.
//
// Any 2xx response is accepted regardless of media type or body content. The
// body is consumed only to enforce the configured limit and populate status
// errors.
//
// Parameters:
//   - operation: The operation name placed on structured errors.
//   - method: The HTTP method placed on structured errors.
//   - response: The HTTP response to consume and validate.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - err: An *Error for response-limit, response-body, or HTTP-status failures;
//     otherwise nil.
func readRewriteMutationResponse(
	operation string,
	method string,
	response *http.Response,
	limit int64,
) *Error {
	body, tooLarge, readErr := readBounded(response.Body, limit)
	closeErr := response.Body.Close()

	switch {
	case tooLarge:
		clientErr := responseError(operation, ErrorKindResponseTooLarge, response, nil)

		clientErr.Method = method
		clientErr.Limit = limit

		return clientErr
	case readErr != nil:
		clientErr := responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errReadResponse, readErr),
		)

		clientErr.Method = method

		return clientErr
	case closeErr != nil:
		clientErr := responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errCloseResponse, closeErr),
		)

		clientErr.Method = method

		return clientErr
	case response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices:
		return statusError(
			operation,
			method,
			response.StatusCode,
			response.Status,
			response.Header.Get("Content-Type"),
			body,
		)
	default:
		return nil
	}
}

// rewriteJSONError creates a structured rewrite response decoding error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - cause: The JSON decoding or response-contract cause.
//
// Returns:
//   - err: The structured JSON error with the GET method metadata.
func rewriteJSONError(operation string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = http.MethodGet
	clientErr.Err = cause

	return clientErr
}
