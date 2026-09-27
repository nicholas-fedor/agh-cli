// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
)

// SafetyService groups safe-browsing, parental-control, and safe-search
// operations.
type SafetyService interface {
	SafebrowsingDisable(ctx context.Context) error
	SafebrowsingEnable(ctx context.Context) error
	SafebrowsingStatus(ctx context.Context) (*SafebrowsingStatus, error)
	ParentalDisable(ctx context.Context) error
	ParentalEnable(ctx context.Context) error
	ParentalStatus(ctx context.Context) (*ParentalStatus, error)
	SafesearchSettings(ctx context.Context, config SafeSearchConfig) error
	SafesearchStatus(ctx context.Context) (*SafeSearchConfig, error)

	// Deprecated: Use SafesearchSettings with SafeSearchConfig.Enabled instead.
	SafesearchEnable(ctx context.Context) error
	// Deprecated: Use SafesearchSettings with SafeSearchConfig.Enabled instead.
	SafesearchDisable(ctx context.Context) error
}

// SafebrowsingStatus contains the safe-browsing protection state.
//
// Enabled is optional. Nil omits the field in a request and represents an
// absent or null value in a response.
type SafebrowsingStatus struct {
	// Enabled is the optional safe-browsing protection state.
	Enabled *bool `json:"enabled,omitempty"`
}

// ParentalStatus contains the response-only parental-control state and
// sensitivity.
//
// Both fields are optional. Nil represents an absent or null response value.
type ParentalStatus struct {
	// Enabled is the optional parental-control protection state.
	Enabled *bool `json:"enabled,omitempty"`
	// Sensitivity is the optional parental-control sensitivity.
	Sensitivity *int64 `json:"sensitivity,omitempty"`
}

const (
	// SafetySafebrowsingEnableOperation identifies SafebrowsingEnable errors.
	safetySafebrowsingEnableOperation = "safebrowsing_enable"
	// SafetySafebrowsingDisableOperation identifies SafebrowsingDisable errors.
	safetySafebrowsingDisableOperation = "safebrowsing_disable"
	// SafetySafebrowsingStatusOperation identifies SafebrowsingStatus errors.
	safetySafebrowsingStatusOperation = "safebrowsing_status"
	// SafetyParentalEnableOperation identifies ParentalEnable errors.
	safetyParentalEnableOperation = "parental_enable"
	// SafetyParentalDisableOperation identifies ParentalDisable errors.
	safetyParentalDisableOperation = "parental_disable"
	// SafetyParentalStatusOperation identifies ParentalStatus errors.
	safetyParentalStatusOperation = "parental_status"
	// SafetySafesearchSettingsOperation identifies SafesearchSettings errors.
	safetySafesearchSettingsOperation = "safesearch_settings"
	// SafetySafesearchStatusOperation identifies SafesearchStatus errors.
	safetySafesearchStatusOperation = "safesearch_status"
)

// ErrNullSafetyResponse identifies a top-level null safety status response.
var errNullSafetyResponse = errors.New("safety response must be a JSON object")

var _ SafetyService = (*Client)(nil)

// ParentalDisable disables parental control.
//
// The request has no body. Any 2xx response is accepted without interpreting
// its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) ParentalDisable(ctx context.Context) error {
	requestErr := c.postNoContent(
		ctx,
		safetyParentalDisableOperation,
		"control/parental/disable",
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ParentalEnable enables parental control.
//
// The request has no body. Any 2xx response is accepted without interpreting
// its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) ParentalEnable(ctx context.Context) error {
	requestErr := c.postNoContent(
		ctx,
		safetyParentalEnableOperation,
		"control/parental/enable",
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ParentalStatus retrieves the parental-control state and sensitivity.
//
// The successful response must use a JSON media type and contain a non-null
// object. Both fields are optional; absent and null values decode to nil, while
// explicit false and zero values are preserved.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - status: The decoded parental-control status when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or null-object failures; otherwise nil.
func (c *Client) ParentalStatus(ctx context.Context) (*ParentalStatus, error) {
	response, requestErr := c.get(ctx, safetyParentalStatusOperation, "control/parental/status")
	if requestErr != nil {
		return nil, requestErr
	}

	status, decodeErr := decodeSafetyObject[ParentalStatus](
		safetyParentalStatusOperation,
		response.body,
	)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return status, nil
}

// SafebrowsingDisable disables safe-browsing protection.
//
// The request has no body. Any 2xx response is accepted without interpreting
// its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) SafebrowsingDisable(ctx context.Context) error {
	requestErr := c.postNoContent(
		ctx,
		safetySafebrowsingDisableOperation,
		"control/safebrowsing/disable",
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// SafebrowsingEnable enables safe-browsing protection.
//
// The request has no body. Any 2xx response is accepted without interpreting
// its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) SafebrowsingEnable(ctx context.Context) error {
	requestErr := c.postNoContent(
		ctx,
		safetySafebrowsingEnableOperation,
		"control/safebrowsing/enable",
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// SafebrowsingStatus retrieves the safe-browsing protection state.
//
// The successful response must use a JSON media type and contain a non-null
// object. Enabled is optional; absent and null values decode to nil, while
// explicit false is preserved.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - status: The decoded safe-browsing status when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or null-object failures; otherwise nil.
func (c *Client) SafebrowsingStatus(ctx context.Context) (*SafebrowsingStatus, error) {
	response, requestErr := c.get(
		ctx,
		safetySafebrowsingStatusOperation,
		"control/safebrowsing/status",
	)
	if requestErr != nil {
		return nil, requestErr
	}

	status, decodeErr := decodeSafetyObject[SafebrowsingStatus](
		safetySafebrowsingStatusOperation,
		response.body,
	)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return status, nil
}

// SafesearchSettings updates the safe-search configuration.
//
// The config value is always encoded as a JSON object. Nil provider fields are
// omitted, while nonnil fields preserve explicit false values. Any 2xx response
// is accepted without interpreting its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The safe-search settings to apply.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) SafesearchSettings(
	ctx context.Context,
	config SafeSearchConfig,
) error {
	requestErr := c.postEmpty(
		ctx,
		safetySafesearchSettingsOperation,
		http.MethodPut,
		"control/safesearch/settings",
		config,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// SafesearchStatus retrieves the safe-search configuration.
//
// The successful response must use a JSON media type and contain a non-null
// object. Every field is optional; absent and null values decode to nil, while
// explicit false values are preserved.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - config: The decoded safe-search configuration when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or null-object failures; otherwise nil.
func (c *Client) SafesearchStatus(ctx context.Context) (*SafeSearchConfig, error) {
	response, requestErr := c.get(ctx, safetySafesearchStatusOperation, "control/safesearch/status")
	if requestErr != nil {
		return nil, requestErr
	}

	status, decodeErr := decodeSafetyObject[SafeSearchConfig](
		safetySafesearchStatusOperation,
		response.body,
	)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return status, nil
}

// decodeSafetyObject strictly decodes a non-null JSON safety status object.
//
// Parameters:
//   - operation: The operation name placed on structured errors.
//   - body: The bounded JSON response body.
//
// Returns:
//   - value: The decoded object when the response is valid.
//   - err: A JSON-kind *Error for malformed JSON or a null object; otherwise nil.
func decodeSafetyObject[T any](operation string, body []byte) (*T, *Error) {
	var value *T

	err := json.Unmarshal(body, &value)
	if err != nil {
		return nil, safetyJSONError(operation, fmt.Errorf("decode response: %w", err))
	}
	if value == nil {
		return nil, safetyJSONError(operation, errNullSafetyResponse)
	}

	return value, nil
}

// safetyJSONError creates a structured safety response decoding error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - cause: The JSON decoding or response-contract cause.
//
// Returns:
//   - err: The structured JSON error with the GET method metadata.
func safetyJSONError(operation string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = http.MethodGet
	clientErr.Err = cause

	return clientErr
}
