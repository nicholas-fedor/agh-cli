// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"
)

// Client is a concurrency-safe AdGuard Home API client.
//
// A Client uses the immutable settings captured by [NewClient]. It is safe for
// concurrent use by multiple goroutines. Every request sends the configured
// User-Agent and optional HTTP Basic credentials. JSON requests also accept
// application/json. Redirects are rejected before a redirected request can be
// sent, and response bodies are read only within the configured size limit.
type Client struct {
	// baseURL is the validated server URL and optional API path prefix.
	baseURL url.URL
	// httpClient is the private client clone used for every request.
	httpClient *http.Client
	// basicAuth reports whether requests include HTTP Basic credentials.
	basicAuth bool
	// username is the configured HTTP Basic authentication username.
	username string
	// password is the configured HTTP Basic authentication password.
	password string
	// requestTimeout bounds each complete request and response-body read.
	requestTimeout time.Duration
	// maxResponseBytes is the maximum response body size accepted by the client.
	maxResponseBytes int64
	// userAgent is the value sent in the User-Agent request header.
	userAgent string
}

// apiResponse contains a bounded, validated JSON response body.
type apiResponse struct {
	// body contains the complete response body after status and media-type
	// validation.
	body []byte
}

// redirectError identifies a response rejected by the redirect policy.
type redirectError struct {
	// location is the absolute URL of the redirect that was not followed.
	location string
}

// jsonContentType is the media type accepted by the shared JSON response path.
const jsonContentType = "application/json"

// The shared tri-state status values below are the wire values that several
// domain response enums report. Domains convert them into their own named
// types, so the shared constants stay untyped strings.
const (
	// StatusValueYes is the shared affirmative status value.
	statusValueYes = "yes"
	// StatusValueNo is the shared negative status value.
	statusValueNo = "no"
	// StatusValueError is the shared failure status value.
	statusValueError = "error"
)

var (
	// ErrCreateRequest identifies request construction failures.
	errCreateRequest = errors.New("create request")
	// ErrReadResponse identifies response body read failures.
	errReadResponse = errors.New("read response body")
	// ErrCloseResponse identifies response body close failures.
	errCloseResponse = errors.New("close response body")
	// ErrParseContentType identifies malformed media type parameters.
	errParseContentType = errors.New("parse content type")
	// ErrUnexpectedJSONType identifies a non-JSON successful response.
	errUnexpectedJSONType = errors.New("content type must be application/json")
	// ErrRedirectRejected identifies a blocked redirect.
	errRedirectRejected = errors.New("redirect rejected")
)

// NewClient creates a client for an AdGuard Home server.
//
// The baseURL value must be absolute, include a host, and use HTTPS. Plain HTTP
// is accepted only for localhost or a loopback IP address. The URL must not
// contain user information, a query, or a fragment. A URL path is retained as
// the prefix for every control endpoint.
//
// Options are applied in order, so a later option overrides an earlier setting
// for the same field. Unless configured otherwise, the client uses a clone of
// [http.DefaultClient], sends no authentication, applies a 30-second timeout to
// each complete request, accepts at most 1 MiB of response-body data, and uses
// "agh-cli-adguard-client/1" as its User-Agent. [WithBasicAuth] enables HTTP
// Basic authentication for every request. The client rejects every redirect,
// and the configured HTTP client's Timeout may end a request earlier than the
// client's request context.
//
// A nil option or an invalid base URL, HTTP client, timeout, response limit,
// or User-Agent produces an [Error] with [ErrorKindConfig].
//
// Parameters:
//   - baseURL: The absolute AdGuard Home server URL and optional API path prefix.
//   - options: Optional [Option] values applied in the supplied order.
//
// Returns:
//   - client: The configured client when construction succeeds.
//   - err: An [Error] with [ErrorKindConfig] when validation fails; otherwise
//     nil.
//
// Example:
//
//	client, err := NewClient(
//		"https://adguard.example",
//		WithBasicAuth("username", "password"),
//		WithRequestTimeout(10*time.Second),
//	)
//	if err != nil {
//		return err
//	}
//	return client.Status(context.Background())
func NewClient(baseURL string, options ...Option) (*Client, error) {
	cfg, err := newConfig(baseURL, options)
	if err != nil {
		return nil, fmt.Errorf("configure client: %w", err)
	}

	return &Client{
		baseURL:          cfg.baseURL,
		httpClient:       cfg.httpClient,
		basicAuth:        cfg.basicAuth,
		username:         cfg.username,
		password:         cfg.password,
		requestTimeout:   cfg.requestTimeout,
		maxResponseBytes: cfg.maxResponseBytes,
		userAgent:        cfg.userAgent,
	}, nil
}

// endpoint resolves an API endpoint against the configured base URL.
//
// The endpoint is joined below the base URL's path prefix, and the resulting
// path is cleaned. The base URL cannot contain a query or fragment, so the
// resolved URL retains only the scheme, authority, and joined path.
//
// Parameters:
//   - endpoint: The control endpoint relative to the client's base URL.
//
// Returns:
//   - The resolved endpoint URL.
func (c *Client) endpoint(endpoint string) url.URL {
	endpointURL := c.baseURL

	endpointURL.Path = path.Join("/", c.baseURL.Path, endpoint)
	endpointURL.RawPath = ""

	return endpointURL
}

// executeRequest sends a prepared request through the configured client.
//
// Transport failures, context cancellation, and rejected redirects are mapped
// to structured errors. The request must already carry the operation context
// and headers.
//
// Parameters:
//   - ctx: The request context used to preserve its cancellation cause.
//   - operation: The operation name placed on a structured request error.
//   - request: The prepared HTTP request to send.
//
// Returns:
//   - response: The HTTP response when the transport completes the request.
//   - err: An [Error] with [ErrorKindRequest] or [ErrorKindRedirect]; otherwise
//     nil.
func (c *Client) executeRequest(
	ctx context.Context,
	operation string,
	request *http.Request,
) (*http.Response, *Error) {
	response, err := c.httpClient.Do(request)
	if err != nil {
		return nil, requestError(ctx, operation, err)
	}

	return response, nil
}

// get executes and validates a JSON GET operation.
//
// The method derives a request context whose effective deadline is the earlier
// of ctx's deadline and the configured request timeout. Parent cancellation
// and the derived timeout therefore stop both transport and response-body
// reads. A response body is accepted when its size is at most the configured
// limit; the client detects a larger body without retaining the excess byte.
//
// The response body is always closed. A 2xx response must advertise a parseable
// application/json media type, optionally with parameters. A non-2xx response
// is returned as [ErrorKindStatus] with its bounded body, without applying the
// successful-response media-type check.
//
// Parameters:
//   - ctx: The parent request context. Its cancellation or earlier deadline ends
//     the operation.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's base URL.
//
// Returns:
//   - response: The bounded, validated JSON response body.
//   - err: An [Error] for request, redirect, status, response-size,
//     response-body, or media-type failures; otherwise nil.
func (c *Client) get(ctx context.Context, operation, endpoint string) (*apiResponse, *Error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newRequest(requestContext, operation, endpoint)
	if requestErr != nil {
		cancel()

		return nil, requestErr
	}

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		cancel()

		return nil, requestErr
	}

	apiResponse, responseErr := readAPIResponse(operation, response, c.maxResponseBytes)

	cancel()

	return apiResponse, responseErr
}

// newRequest creates a JSON GET request with the client's standard headers.
//
// The request has no body, accepts application/json, identifies the configured
// User-Agent, and includes HTTP Basic credentials only when [WithBasicAuth] was
// applied.
//
// Parameters:
//   - ctx: The request context controlling the complete HTTP operation.
//   - operation: The operation name placed on a request-construction error.
//   - endpoint: The control endpoint relative to the client's base URL.
//
// Returns:
//   - request: The prepared GET request.
//   - err: An [Error] with [ErrorKindRequest] when request construction fails;
//     otherwise nil.
func (c *Client) newRequest(
	ctx context.Context,
	operation string,
	endpoint string,
) (*http.Request, *Error) {
	requestURL := c.endpoint(endpoint)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), http.NoBody)
	if err != nil {
		return nil, responseError(
			operation,
			ErrorKindRequest,
			nil,
			fmt.Errorf("%w: %w", errCreateRequest, err),
		)
	}

	request.Header.Set("Accept", jsonContentType)
	request.Header.Set("User-Agent", c.userAgent)

	if c.basicAuth {
		request.SetBasicAuth(c.username, c.password)
	}

	return request, nil
}

// requestError classifies transport, context, and redirect failures.
//
// A wrapped [redirectError] produces [ErrorKindRedirect] and records the target
// in [Error].Location. Other transport failures produce [ErrorKindRequest]. If
// the request context has a cancellation or deadline cause, that cause replaces
// the transport error so callers can match it with [errors.Is].
//
// Parameters:
//   - ctx: The request context whose cause, when present, becomes the error
//     cause.
//   - operation: The operation name placed on the structured error.
//   - err: The transport or redirect error returned by the HTTP client.
//
// Returns:
//   - The structured request or redirect error.
func requestError(ctx context.Context, operation string, err error) *Error {
	kind := ErrorKindRequest
	location := ""
	if redirectErr, ok := errors.AsType[*redirectError](err); ok {
		kind = ErrorKindRedirect
		location = redirectErr.location
	}

	cause := context.Cause(ctx)
	if cause == nil {
		cause = err
	}

	clientErr := newError(kind)

	clientErr.Operation = operation
	clientErr.Method = http.MethodGet
	clientErr.Location = location
	clientErr.Err = cause

	return clientErr
}

// rejectRedirect blocks every redirect before credentials can be forwarded.
//
// This function is installed as the HTTP client's CheckRedirect callback. The
// request argument is the prospective redirected request; the unused via slice
// contains requests already attempted for the current operation.
//
// Parameters:
//   - request: The prospective redirected request that will not be sent.
//
// Returns:
//   - A [redirectError] containing the absolute rejected target URL.
func rejectRedirect(request *http.Request, _ []*http.Request) error {
	return &redirectError{
		location: request.URL.String(),
	}
}

// Error returns the rejected redirect location.
//
// Returns:
//   - The redirect rejection message and absolute target URL.
func (err *redirectError) Error() string {
	return fmt.Errorf("%w: %s", errRedirectRejected, err.location).Error()
}

// readAPIResponse reads, bounds, closes, and validates an HTTP response.
//
// The body is read up to limit, and one additional byte is inspected when the
// body reaches that size. A body of exactly limit bytes is accepted; any larger
// body produces [ErrorKindResponseTooLarge]. The body is closed after every read
// attempt. An oversized body takes precedence over read and close failures,
// followed by a read failure and then a close failure. Status and media-type
// validation runs only after the body has been read and closed successfully.
//
// Parameters:
//   - operation: The operation name placed on a structured response error.
//   - response: The HTTP response whose body must be consumed and closed.
//   - limit: The maximum accepted response body size in bytes. It must be
//     positive.
//
// Returns:
//   - The bounded response body after successful validation.
//   - An [Error] for response-size, response-body, HTTP-status, or media-type
//     failures; otherwise nil.
func readAPIResponse(
	operation string,
	response *http.Response,
	limit int64,
) (*apiResponse, *Error) {
	body, tooLarge, readErr := readBounded(response.Body, limit)
	closeErr := response.Body.Close()

	switch {
	case tooLarge:
		clientErr := responseError(
			operation,
			ErrorKindResponseTooLarge,
			response,
			nil,
		)

		clientErr.Limit = limit

		return nil, clientErr
	case readErr != nil:
		return nil, responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errReadResponse, readErr),
		)
	case closeErr != nil:
		return nil, responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errCloseResponse, closeErr),
		)
	default:
	}

	validationErr := validateAPIResponse(operation, response, body)
	if validationErr != nil {
		return nil, validationErr
	}

	return &apiResponse{body: body}, nil
}

// validateAPIResponse enforces status and media type policies.
//
// Status validation runs first. Any status outside the 2xx range produces
// [ErrorKindStatus] with the bounded response body and raw Content-Type header.
// A successful response must contain a parseable media type equal to
// application/json, ignoring case; parameters such as charset are allowed.
//
// Parameters:
//   - operation: The operation name placed on a structured response error.
//   - response: The HTTP response whose status and Content-Type header validate.
//   - body: The already bounded response body retained for status errors.
//
// Returns:
//   - An [Error] for an HTTP-status or media-type failure; otherwise nil.
func validateAPIResponse(operation string, response *http.Response, body []byte) *Error {
	contentType := response.Header.Get("Content-Type")
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return statusError(
			operation,
			http.MethodGet,
			response.StatusCode,
			response.Status,
			contentType,
			body,
		)
	}

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return responseError(
			operation,
			ErrorKindContentType,
			response,
			fmt.Errorf("%w: %w", errParseContentType, err),
		)
	}
	if !strings.EqualFold(mediaType, jsonContentType) {
		return responseError(
			operation,
			ErrorKindContentType,
			response,
			fmt.Errorf("%w: %s", errUnexpectedJSONType, mediaType),
		)
	}

	return nil
}

// responseError creates a structured error from an HTTP response.
//
// The helper initializes Method to GET because the shared response path serves
// JSON GET operations. Callers for other HTTP methods replace Method before
// returning the error. When response is nil, response metadata remains unset.
//
// Parameters:
//   - operation: The operation name placed on the structured error.
//   - kind: The [ErrorKind] assigned to the error.
//   - response: The response whose status metadata is copied, or nil.
//   - cause: The underlying cause exposed through [Error.Unwrap], or nil.
//
// Returns:
//   - The structured response error.
func responseError(
	operation string,
	kind ErrorKind,
	response *http.Response,
	cause error,
) *Error {
	clientErr := newError(kind)

	clientErr.Operation = operation
	clientErr.Method = http.MethodGet
	clientErr.Err = cause

	if response != nil {
		clientErr.Status = response.Status
		clientErr.StatusCode = response.StatusCode
		clientErr.ContentType = response.Header.Get("Content-Type")
	}

	return clientErr
}

// readBounded reads at most limit bytes and reports whether more data exists.
//
// When the reader ends before limit, the complete body is returned. When it
// reaches limit, the helper reads one probe byte without retaining it: EOF means
// that the body is exactly at the limit, while a successful probe means that the
// body is too large. Other read or probe failures are returned as errors.
//
// Parameters:
//   - reader: The response body reader to consume.
//   - limit: The maximum body size to retain. It must be positive.
//
// Returns:
//   - body: The retained body, or nil when the body is too large or reading
//     fails.
//   - tooLarge: Whether at least one byte exists beyond limit.
//   - err: The bounded-read failure, if any.
func readBounded(reader io.Reader, limit int64) ([]byte, bool, error) {
	var body bytes.Buffer

	written, err := io.CopyN(&body, reader, limit)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("copy response body: %w", err)
	}
	if written < limit {
		return body.Bytes(), false, nil
	}

	var extra [1]byte

	_, err = io.ReadFull(reader, extra[:])
	if err == nil {
		return nil, true, nil
	}
	if errors.Is(err, io.EOF) {
		return body.Bytes(), false, nil
	}

	return nil, false, fmt.Errorf("check response body limit: %w", err)
}
