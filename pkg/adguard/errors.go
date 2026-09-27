// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"strings"
)

// ErrorKind classifies an [Error].
//
// Callers should compare Kind with the documented [ErrorKind] constants. The
// underlying string is intended for programmatic inspection and diagnostics,
// not presentation.
type ErrorKind string

// Error is the structured error returned by client operations.
//
// Client methods return this type through the standard error interface. Use
// [errors.AsType] to obtain an *Error, then inspect Kind and the fields relevant
// to that kind. Fields not documented for a failure remain at their zero value.
// In particular, Status metadata requires a received response, Body is limited
// to a bounded non-success response, Limit applies to oversized responses, and
// Location applies to rejected redirects.
//
// The wrapped cause supports [errors.Is], so context cancellation, deadline
// expiration, and transport causes remain matchable.
type Error struct {
	// Kind classifies the failure.
	Kind ErrorKind
	// Operation identifies the client operation, or is empty when no operation
	// has started.
	Operation string
	// Method identifies the HTTP method when known.
	Method string
	// Status is the HTTP status line when a response was received.
	Status string
	// StatusCode is the HTTP status code when a response was received.
	StatusCode int
	// ContentType is the raw response Content-Type header when available.
	ContentType string
	// Body contains the bounded response body for a non-success HTTP status.
	Body []byte
	// Limit is the configured response body limit for an oversized response.
	Limit int64
	// Location is the rejected redirect target when relevant.
	Location string
	// Err is the underlying cause when one is available.
	Err error
}

const (
	// ErrorKindConfig identifies invalid client configuration or operation input.
	ErrorKindConfig ErrorKind = "config"
	// ErrorKindRequest identifies request construction, validation, transport,
	// context-cancellation, or deadline failures.
	ErrorKindRequest ErrorKind = "request"
	// ErrorKindStatus identifies a received HTTP response outside the accepted
	// 2xx success range.
	ErrorKindStatus ErrorKind = "status"
	// ErrorKindContentType identifies a successful response with a missing,
	// malformed, or unexpected media type.
	ErrorKindContentType ErrorKind = "content_type"
	// ErrorKindResponseTooLarge identifies a response body larger than the limit
	// configured by [WithMaxResponseBodySize].
	ErrorKindResponseTooLarge ErrorKind = "response_too_large"
	// ErrorKindResponseBody identifies a failure while reading or closing a
	// response body.
	ErrorKindResponseBody ErrorKind = "response_body"
	// ErrorKindJSON identifies JSON encoding, decoding, or response-contract
	// validation failures.
	ErrorKindJSON ErrorKind = "json"
	// ErrorKindRedirect identifies a redirect rejected before the redirected
	// request was sent.
	ErrorKindRedirect ErrorKind = "redirect"
)

// Error returns a concise description of the client error.
//
// A nil receiver returns "<nil>". Otherwise the description starts with
// "adguard", includes Operation when present, and then includes Kind. It adds
// Status for [ErrorKindStatus], Location for [ErrorKindRedirect], or the wrapped
// cause when available, in that priority. Other structured fields are omitted
// from the string and should be inspected directly.
//
// Returns:
//   - The concise error description.
func (err *Error) Error() string {
	if err == nil {
		return "<nil>"
	}

	parts := []string{"adguard"}
	if err.Operation != "" {
		parts = append(parts, err.Operation)
	}

	parts = append(parts, string(err.Kind))

	switch {
	case err.Kind == ErrorKindStatus && err.Status != "":
		parts = append(parts, err.Status)
	case err.Kind == ErrorKindRedirect && err.Location != "":
		parts = append(parts, err.Location)
	case err.Err != nil:
		parts = append(parts, err.Err.Error())
	default:
	}

	return strings.Join(parts, ": ")
}

// Unwrap returns the underlying cause.
//
// The nil-safe result supports [errors.Is] and [errors.As] traversal without
// exposing the [Error] fields as wrapper causes.
//
// Returns:
//   - The underlying cause, or nil when the receiver or Err is nil.
func (err *Error) Unwrap() error {
	if err == nil {
		return nil
	}

	return err.Err
}

// newError creates a fully initialized structured error.
//
// All diagnostic fields other than Kind are initialized to their zero values so
// constructors can populate only those relevant to a failure kind.
//
// Parameters:
//   - kind: The [ErrorKind] assigned to the new error.
//
// Returns:
//   - A new structured error with the requested kind.
func newError(kind ErrorKind) *Error {
	return &Error{
		Kind:        kind,
		Operation:   "",
		Method:      "",
		Status:      "",
		StatusCode:  0,
		ContentType: "",
		Body:        nil,
		Limit:       0,
		Location:    "",
		Err:         nil,
	}
}

// configError creates a structured configuration error.
//
// The helper leaves Operation and HTTP response metadata unset because
// configuration is validated before an operation starts.
//
// Parameters:
//   - err: The configuration or option-validation cause.
//
// Returns:
//   - An [Error] with [ErrorKindConfig] and the supplied cause.
func configError(err error) *Error {
	clientErr := newError(ErrorKindConfig)

	clientErr.Err = err

	return clientErr
}

// statusError creates a structured non-success response error.
//
// The body must already satisfy the configured response limit. This helper
// records response metadata but does not wrap a cause or set Limit or Location.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method used for the request.
//   - statusCode: The received HTTP status code.
//   - status: The received HTTP status line.
//   - contentType: The raw response Content-Type header.
//   - body: The bounded response body.
//
// Returns:
//   - An [Error] with [ErrorKindStatus] and the supplied response metadata.
func statusError(operation, method string, statusCode int, status, contentType string, body []byte) *Error {
	clientErr := newError(ErrorKindStatus)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Status = status
	clientErr.StatusCode = statusCode
	clientErr.ContentType = contentType
	clientErr.Body = body

	return clientErr
}
