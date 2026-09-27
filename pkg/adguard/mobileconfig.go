// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
)

// MobileConfigService downloads bounded DoH and DoT configuration artifacts.
type MobileConfigService interface {
	DownloadDoH(ctx context.Context, request MobileConfigRequest) (Artifact, error)
	DownloadDoT(ctx context.Context, request MobileConfigRequest) (Artifact, error)
}

// MobileConfigRequest identifies the host and optional client for a mobile
// configuration download.
//
// Host is required. ClientID is optional; a nonnil pointer is encoded as the
// client_id query parameter even when its value is empty.
type MobileConfigRequest struct {
	// Host is the validated server name used to generate the configuration.
	Host string
	// ClientID is the optional encrypted-DNS client identifier. Nil omits the
	// client_id query parameter.
	ClientID *string
}

// Artifact contains one bounded binary response returned by the client.
//
// Data contains the response bytes without text decoding or transformation.
// ContentType contains the response Content-Type header verbatim and may be
// empty when the server did not provide one.
type Artifact struct {
	// ContentType is the response media type when supplied by the server.
	ContentType string
	// Data contains the bounded response bytes.
	Data []byte
}

const (
	// MobileConfigDoHOperation identifies DNS-over-HTTPS configuration errors.
	mobileConfigDoHOperation = "mobile_config_doh"
	// MobileConfigDoTOperation identifies DNS-over-TLS configuration errors.
	mobileConfigDoTOperation = "mobile_config_dot"
	// MobileConfigDoHEndpoint is the DNS-over-HTTPS configuration path.
	mobileConfigDoHEndpoint = "control/apple/doh.mobileconfig"
	// MobileConfigDoTEndpoint is the DNS-over-TLS configuration path.
	mobileConfigDoTEndpoint = "control/apple/dot.mobileconfig"
	// MobileConfigMaxHostLength bounds the host query value in bytes.
	mobileConfigMaxHostLength = 253
	// MobileConfigAccept requests a binary response without requiring JSON.
	mobileConfigAccept = "application/octet-stream"
)

var (
	_ MobileConfigService = (*Client)(nil)
	// ErrMobileConfigHostRequired identifies an empty or whitespace-only host.
	errMobileConfigHostRequired = errors.New("mobile config host is required")
	// ErrMobileConfigHostTooLong identifies a host longer than 253 bytes.
	errMobileConfigHostTooLong = errors.New("mobile config host is too long")
	// ErrMobileConfigHostInvalid identifies a host containing Unicode whitespace
	// or control characters.
	errMobileConfigHostInvalid = errors.New("mobile config host contains invalid characters")
)

// DownloadDoH downloads a DNS-over-HTTPS mobile configuration.
//
// The host is validated before transport. The response is treated as opaque
// binary data: any 2xx status and media type are accepted, and the bytes are
// returned without JSON or text decoding. The response is bounded by the
// configured limit.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The host and optional encrypted-DNS client identifier.
//
// Returns:
//   - artifact: The bounded configuration bytes and reported content type.
//   - err: An error wrapping local validation, request, redirect, HTTP,
//     response-limit, or response-body failures; otherwise nil.
func (c *Client) DownloadDoH(
	ctx context.Context,
	request MobileConfigRequest,
) (Artifact, error) {
	artifact, err := c.downloadMobileConfig(ctx, mobileConfigDoHOperation, mobileConfigDoHEndpoint, request)
	if err != nil {
		return Artifact{}, fmt.Errorf("download DNS-over-HTTPS mobile configuration: %w", err)
	}

	return artifact, nil
}

// DownloadDoT downloads a DNS-over-TLS mobile configuration.
//
// The host is validated before transport. The response is treated as opaque
// binary data: any 2xx status and media type are accepted, and the bytes are
// returned without JSON or text decoding. The response is bounded by the
// configured limit.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The host and optional encrypted-DNS client identifier.
//
// Returns:
//   - artifact: The bounded configuration bytes and reported content type.
//   - err: An error wrapping local validation, request, redirect, HTTP,
//     response-limit, or response-body failures; otherwise nil.
func (c *Client) DownloadDoT(
	ctx context.Context,
	request MobileConfigRequest,
) (Artifact, error) {
	artifact, err := c.downloadMobileConfig(ctx, mobileConfigDoTOperation, mobileConfigDoTEndpoint, request)
	if err != nil {
		return Artifact{}, fmt.Errorf("download DNS-over-TLS mobile configuration: %w", err)
	}

	return artifact, nil
}

// MobileConfigDoH downloads a DNS-over-HTTPS mobile configuration.
//
// This operation is an alias of DownloadDoH and applies the same opaque binary
// response and bounded-read behavior.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The host and optional encrypted-DNS client identifier.
//
// Returns:
//   - artifact: The bounded configuration bytes and reported content type.
//   - err: An error wrapping local validation, request, redirect, HTTP,
//     response-limit, or response-body failures; otherwise nil.
func (c *Client) MobileConfigDoH(
	ctx context.Context,
	request MobileConfigRequest,
) (Artifact, error) {
	artifact, err := c.DownloadDoH(ctx, request)
	if err != nil {
		return Artifact{}, fmt.Errorf("download DNS-over-HTTPS mobile configuration: %w", err)
	}

	return artifact, nil
}

// MobileConfigDoT downloads a DNS-over-TLS mobile configuration.
//
// This operation is an alias of DownloadDoT and applies the same opaque binary
// response and bounded-read behavior.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The host and optional encrypted-DNS client identifier.
//
// Returns:
//   - artifact: The bounded configuration bytes and reported content type.
//   - err: An error wrapping local validation, request, redirect, HTTP,
//     response-limit, or response-body failures; otherwise nil.
func (c *Client) MobileConfigDoT(
	ctx context.Context,
	request MobileConfigRequest,
) (Artifact, error) {
	artifact, err := c.DownloadDoT(ctx, request)
	if err != nil {
		return Artifact{}, fmt.Errorf("download DNS-over-TLS mobile configuration: %w", err)
	}

	return artifact, nil
}

// downloadMobileConfig validates, requests, and reads a bounded opaque binary
// mobile configuration response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - mobileRequest: The host and optional encrypted-DNS client identifier.
//
// Returns:
//   - artifact: The bounded configuration bytes and reported content type.
//   - err: An *Error for validation, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) downloadMobileConfig(
	ctx context.Context,
	operation string,
	endpoint string,
	mobileRequest MobileConfigRequest,
) (Artifact, error) {
	validationErr := validateMobileConfigRequest(mobileRequest)
	if validationErr != nil {
		return Artifact{}, responseError(operation, ErrorKindRequest, nil, validationErr)
	}

	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newMobileConfigRequest(requestContext, operation, endpoint, mobileRequest)
	if requestErr != nil {
		cancel()

		return Artifact{}, requestErr
	}

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		cancel()

		return Artifact{}, requestErr
	}

	artifact, responseErr := readMobileConfigResponse(operation, response, c.maxResponseBytes)

	cancel()

	if responseErr != nil {
		return Artifact{}, responseErr
	}

	return artifact, nil
}

// newMobileConfigRequest creates an authenticated opaque-binary GET request.
//
// The request has no body or request content type. It always sends a host query
// parameter and sends client_id only when ClientID is nonnil.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - mobileRequest: The validated host and optional client identifier.
//
// Returns:
//   - request: The prepared HTTP request.
//   - err: A request-kind *Error when request construction fails; otherwise nil.
func (c *Client) newMobileConfigRequest(
	ctx context.Context,
	operation string,
	endpoint string,
	mobileRequest MobileConfigRequest,
) (*http.Request, *Error) {
	requestURL := c.endpoint(endpoint)
	query := make(url.Values, 2)
	query.Set("host", mobileRequest.Host)

	if mobileRequest.ClientID != nil {
		query.Set("client_id", *mobileRequest.ClientID)
	}

	requestURL.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), http.NoBody)
	if err != nil {
		return nil, responseError(
			operation,
			ErrorKindRequest,
			nil,
			fmt.Errorf("%w: %w", errCreateRequest, err),
		)
	}

	request.Header.Set("Accept", mobileConfigAccept)
	request.Header.Set("User-Agent", c.userAgent)

	if c.basicAuth {
		request.SetBasicAuth(c.username, c.password)
	}

	return request, nil
}

// readMobileConfigResponse reads, bounds, closes, and validates an opaque binary
// mobile configuration response.
//
// Any 2xx response is accepted regardless of media type. Successful body bytes
// are returned without decoding, and the Content-Type header is preserved
// verbatim even when it is empty.
//
// Parameters:
//   - operation: The operation name placed on structured errors.
//   - response: The HTTP response to consume and validate.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - artifact: The bounded response bytes and reported content type.
//   - err: An *Error for response-limit, response-body, or HTTP-status failures;
//     otherwise nil.
func readMobileConfigResponse(
	operation string,
	response *http.Response,
	limit int64,
) (Artifact, *Error) {
	body, tooLarge, readErr := readBounded(response.Body, limit)
	closeErr := response.Body.Close()

	switch {
	case tooLarge:
		clientErr := responseError(operation, ErrorKindResponseTooLarge, response, nil)

		clientErr.Limit = limit

		return Artifact{}, clientErr
	case readErr != nil:
		return Artifact{}, responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errReadResponse, readErr),
		)
	case closeErr != nil:
		return Artifact{}, responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errCloseResponse, closeErr),
		)
	case response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices:
		return Artifact{}, statusError(
			operation,
			http.MethodGet,
			response.StatusCode,
			response.Status,
			response.Header.Get("Content-Type"),
			body,
		)
	default:
		return Artifact{
			ContentType: response.Header.Get("Content-Type"),
			Data:        body,
		}, nil
	}
}

// validateMobileConfigRequest validates the required host query value.
//
// The host must contain at least one non-whitespace byte, must not exceed 253
// bytes, and must not contain Unicode whitespace or control characters.
//
// Parameters:
//   - request: The mobile configuration request to validate.
//
// Returns:
//   - err: An error identifying a missing, oversized, or invalid host; otherwise nil.
func validateMobileConfigRequest(request MobileConfigRequest) error {
	if strings.TrimSpace(request.Host) == "" {
		return errMobileConfigHostRequired
	}
	if len(request.Host) > mobileConfigMaxHostLength {
		return fmt.Errorf("%w: maximum is %d bytes", errMobileConfigHostTooLong, mobileConfigMaxHostLength)
	}

	for _, value := range request.Host {
		if unicode.IsSpace(value) || unicode.IsControl(value) {
			return errMobileConfigHostInvalid
		}
	}

	return nil
}
