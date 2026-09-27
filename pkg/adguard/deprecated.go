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

// deprecatedQueryLogConfigRequest mirrors the legacy query-log configuration request.
type deprecatedQueryLogConfigRequest struct {
	Enabled           bool    `json:"enabled"`
	Interval          float64 `json:"interval"`
	AnonymizeClientIP bool    `json:"anonymize_client_ip"`
}

// deprecatedStatsConfigRequest mirrors the legacy statistics request.
type deprecatedStatsConfigRequest struct {
	Interval float64 `json:"interval"`
}

// deprecatedLanguageRequest mirrors the legacy language request.
type deprecatedLanguageRequest struct {
	Language string `json:"language"`
}

var (
	// The errNullDeprecatedResponse variable identifies a null legacy response.
	errNullDeprecatedResponse = errors.New("deprecated operation response must be a JSON object or array")
	// The errNullDeprecatedArrayElement variable identifies a null string-array element.
	errNullDeprecatedArrayElement = errors.New("deprecated operation response array element must be a string")
	// The errRequiredDeprecatedLanguageField variable identifies an absent language field.
	errRequiredDeprecatedLanguageField = errors.New("deprecated language response field is required")
)

// QueryLogInfo retrieves query-log configuration through the deprecated
// queryLogInfo endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - config: The decoded legacy query-log configuration when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or null-object failures; otherwise nil.
//
// Deprecated: Use GetQueryLogConfig instead.
func (c *Client) QueryLogInfo(ctx context.Context) (*QueryLogConfig, error) {
	response, requestErr := c.get(ctx, "query_log_info", "control/querylog_info")
	if requestErr != nil {
		return nil, requestErr
	}

	config, decodeErr := decodeDeprecatedResponse[QueryLogConfig](
		"query_log_info",
		http.MethodGet,
		response.body,
	)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return config, nil
}

// QueryLogConfig updates query-log configuration through the deprecated
// queryLogConfig endpoint. Only fields defined by the legacy schema are sent.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The legacy query-log configuration to apply.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
//
// Deprecated: Use PutQueryLogConfig instead.
func (c *Client) QueryLogConfig(ctx context.Context, config QueryLogConfig) error {
	requestErr := c.postEmpty(
		ctx,
		"query_log_config",
		http.MethodPost,
		"control/querylog_config",
		deprecatedQueryLogConfigRequest{
			Enabled:           config.Enabled,
			Interval:          config.Interval,
			AnonymizeClientIP: config.AnonymizeClientIP,
		},
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// StatsInfo retrieves statistics configuration through the deprecated statsInfo
// endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - config: The decoded legacy statistics configuration when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or null-object failures; otherwise nil.
//
// Deprecated: Use GetStatsConfig instead.
func (c *Client) StatsInfo(ctx context.Context) (*StatsConfig, error) {
	response, requestErr := c.get(ctx, "stats_info", "control/stats_info")
	if requestErr != nil {
		return nil, requestErr
	}

	config, decodeErr := decodeDeprecatedResponse[StatsConfig](
		"stats_info",
		http.MethodGet,
		response.body,
	)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return config, nil
}

// StatsConfig updates statistics configuration through the deprecated
// statsConfig endpoint. Only the interval defined by the legacy schema is sent.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The statistics configuration containing the legacy interval.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
//
// Deprecated: Use PutStatsConfig instead.
func (c *Client) StatsConfig(ctx context.Context, config StatsConfig) error {
	requestErr := c.postEmpty(
		ctx,
		"stats_config",
		http.MethodPost,
		"control/stats_config",
		deprecatedStatsConfigRequest{Interval: config.Interval},
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// SafesearchEnable enables safe search through the deprecated safesearchEnable
// endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
//
// Deprecated: Use SafesearchSettings with SafeSearchConfig.Enabled instead.
func (c *Client) SafesearchEnable(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, "safesearch_enable", "control/safesearch/enable")
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// SafesearchDisable disables safe search through the deprecated
// safesearchDisable endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
//
// Deprecated: Use SafesearchSettings with SafeSearchConfig.Enabled instead.
func (c *Client) SafesearchDisable(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, "safesearch_disable", "control/safesearch/disable")
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// BlockedServicesAvailableServices retrieves available blocked-service
// identifiers through the deprecated blockedServicesAvailableServices endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - services: The decoded service identifiers, including a nonnil empty slice
//     for an empty JSON array.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, null-array, or null-element failures; otherwise nil.
//
// Deprecated: Use BlockedServicesAll instead.
func (c *Client) BlockedServicesAvailableServices(ctx context.Context) ([]string, error) {
	services, requestErr := c.getDeprecatedStringArray(
		ctx,
		"blocked_services_available_services",
		"control/blocked_services/services",
	)
	if requestErr != nil {
		return nil, requestErr
	}

	return services, nil
}

// BlockedServicesList retrieves configured blocked-service identifiers through
// the deprecated blockedServicesList endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - services: The decoded service identifiers, including a nonnil empty slice
//     for an empty JSON array.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, null-array, or null-element failures; otherwise nil.
//
// Deprecated: Use BlockedServicesSchedule instead.
func (c *Client) BlockedServicesList(ctx context.Context) ([]string, error) {
	services, requestErr := c.getDeprecatedStringArray(
		ctx,
		"blocked_services_list",
		"control/blocked_services/list",
	)
	if requestErr != nil {
		return nil, requestErr
	}

	return services, nil
}

// BlockedServicesSet replaces blocked-service identifiers through the deprecated
// blockedServicesSet endpoint. A nil slice omits the optional request body; a
// nonnil empty slice sends an explicit empty JSON array.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - services: The blocked-service identifiers to apply.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
//
// Deprecated: Use BlockedServicesScheduleUpdate instead.
func (c *Client) BlockedServicesSet(ctx context.Context, services []string) error {
	if services == nil {
		requestErr := c.postNoContent(
			ctx,
			"blocked_services_set",
			"control/blocked_services/set",
		)
		if requestErr != nil {
			return requestErr
		}

		return nil
	}

	requestErr := c.postEmpty(
		ctx,
		"blocked_services_set",
		http.MethodPost,
		"control/blocked_services/set",
		services,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ChangeLanguage changes the web-interface language through the deprecated
// changeLanguage endpoint.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - language: The ISO 639-1 language code to apply. The server validates that
//     the code is supported.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
//
// Deprecated: Use UpdateProfile instead.
func (c *Client) ChangeLanguage(ctx context.Context, language string) error {
	requestErr := c.postEmpty(
		ctx,
		"change_language",
		http.MethodPost,
		"control/i18n/change_language",
		deprecatedLanguageRequest{Language: language},
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// CurrentLanguage retrieves the web-interface language through the deprecated
// currentLanguage endpoint. An empty returned string represents the default
// language.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - language: The current ISO 639-1 language code when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, null-object, or missing-language failures;
//     otherwise nil.
//
// Deprecated: Use GetProfile instead.
func (c *Client) CurrentLanguage(ctx context.Context) (string, error) {
	response, requestErr := c.get(ctx, "current_language", "control/i18n/current_language")
	if requestErr != nil {
		return "", requestErr
	}

	language, decodeErr := decodeDeprecatedLanguage("current_language", response.body)
	if decodeErr != nil {
		return "", decodeErr
	}

	return language, nil
}

// getDeprecatedStringArray retrieves and decodes a legacy string-array response.
func (c *Client) getDeprecatedStringArray(
	ctx context.Context,
	operation string,
	endpoint string,
) ([]string, *Error) {
	response, requestErr := c.get(ctx, operation, endpoint)
	if requestErr != nil {
		return nil, requestErr
	}

	services, decodeErr := decodeDeprecatedStringArray(operation, response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return services, nil
}

// decodeDeprecatedStringArray decodes a non-null legacy JSON string array.
func decodeDeprecatedStringArray(operation string, body []byte) ([]string, *Error) {
	wire, decodeErr := decodeDeprecatedResponse[[]*string](operation, http.MethodGet, body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	services := make([]string, 0, len(*wire))
	for index, service := range *wire {
		if service == nil {
			return nil, deprecatedJSONError(
				operation,
				http.MethodGet,
				fmt.Errorf("element %d: %w", index, errNullDeprecatedArrayElement),
			)
		}

		services = append(services, *service)
	}

	return services, nil
}

// decodeDeprecatedLanguage decodes a legacy language response.
func decodeDeprecatedLanguage(operation string, body []byte) (string, *Error) {
	wire, decodeErr := decodeDeprecatedResponse[struct {
		Language *string `json:"language"`
	}](operation, http.MethodGet, body)
	if decodeErr != nil {
		return "", decodeErr
	}
	if wire.Language == nil {
		return "", deprecatedJSONError(operation, http.MethodGet, errRequiredDeprecatedLanguageField)
	}

	return *wire.Language, nil
}

// decodeDeprecatedResponse decodes a non-null legacy JSON response.
func decodeDeprecatedResponse[T any](
	operation string,
	method string,
	body []byte,
) (*T, *Error) {
	var value *T

	err := json.Unmarshal(body, &value)
	if err != nil {
		return nil, deprecatedJSONError(
			operation,
			method,
			fmt.Errorf("decode response: %w", err),
		)
	}
	if value == nil {
		return nil, deprecatedJSONError(operation, method, errNullDeprecatedResponse)
	}

	return value, nil
}

// deprecatedJSONError creates a structured legacy JSON decoding error.
func deprecatedJSONError(operation, method string, cause error) *Error {
	requestErr := newError(ErrorKindJSON)

	requestErr.Operation = operation
	requestErr.Method = method
	requestErr.Err = cause

	return requestErr
}
