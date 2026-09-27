// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"net/http"
)

// AuthService exposes the Basic-authentication lifecycle operations.
type AuthService interface {
	Login(ctx context.Context, request Login) error
	Logout(ctx context.Context) error
}

// Login contains the optional credentials accepted by the login endpoint.
type Login struct {
	// Name is the login name.
	Name string `json:"name,omitempty"`
	// Password is the login password.
	Password string `json:"password,omitempty"`
}

const (
	// OperationLogin identifies Login errors.
	operationLogin = "login"
	// OperationLogout identifies Logout errors.
	operationLogout = "logout"
)

var _ AuthService = (*Client)(nil)

// Login submits credentials to the AdGuard Home login endpoint.
//
// The request is POST /control/login with a JSON object. The configured
// Basic-auth header is attached by the shared client request policy. The
// response is treated as an empty response mode: its body is bounded and closed
// but is not decoded, and its media type is not required.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional login credentials.
//
// Returns:
//   - err: An [Error] for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) Login(ctx context.Context, request Login) error {
	requestErr := c.postEmpty(
		ctx,
		operationLogin,
		http.MethodPost,
		"control/login",
		request,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// Logout ends the current AdGuard Home session.
//
// The request is GET /control/logout. A declared HTTP 302 response is a success
// and is consumed without following its Location header, so credentials are not
// forwarded to another target. Other 3xx responses are rejected as redirects.
// The response body is bounded and closed in either case.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An [Error] for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) Logout(ctx context.Context) error {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newGlobalRequest(
		requestContext,
		operationLogout,
		http.MethodGet,
		"control/logout",
		http.NoBody,
	)
	if requestErr != nil {
		cancel()

		return requestErr
	}

	logoutClient := *c.httpClient

	logoutClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}

	response, err := logoutClient.Do(request)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}

		cancel()

		requestErr = requestError(ctx, operationLogout, err)
		requestErr.Method = http.MethodGet

		return requestErr
	}

	responseErr := readLogoutResponse(
		operationLogout,
		response,
		c.maxResponseBytes,
	)

	cancel()

	if responseErr != nil {
		return responseErr
	}

	return nil
}

// readLogoutResponse consumes and validates a logout response.
//
// Parameters:
//   - operation: The operation name placed on errors.
//   - response: The bounded response to consume and close.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - nil for the declared 302 response; otherwise a structured error.
func readLogoutResponse(operation string, response *http.Response, limit int64) *Error {
	if response.Body == nil {
		response.Body = http.NoBody
	}

	body, tooLarge, readErr := readBounded(response.Body, limit)
	closeErr := response.Body.Close()

	// A read failure takes precedence over a close failure so the reported
	// cause matches the first error encountered while draining the body.
	bodyErr := readErr
	if bodyErr == nil {
		bodyErr = closeErr
	}

	switch {
	case tooLarge:
		clientErr := responseError(operation, ErrorKindResponseTooLarge, response, nil)

		clientErr.Method = http.MethodGet
		clientErr.Limit = limit

		return clientErr
	case bodyErr != nil:
		clientErr := responseError(operation, ErrorKindResponseBody, response, bodyErr)

		clientErr.Method = http.MethodGet

		return clientErr
	}

	if response.StatusCode == http.StatusFound {
		return nil
	}

	location := response.Header.Get("Location")

	if response.StatusCode >= http.StatusMultipleChoices && response.StatusCode < http.StatusBadRequest {
		clientErr := responseError(
			operation,
			ErrorKindRedirect,
			response,
			&redirectError{location: location},
		)

		clientErr.Method = http.MethodGet
		clientErr.Location = location

		return clientErr
	}

	clientErr := statusError(
		operation,
		http.MethodGet,
		response.StatusCode,
		response.Status,
		response.Header.Get("Content-Type"),
		body,
	)

	clientErr.Method = http.MethodGet

	return clientErr
}
