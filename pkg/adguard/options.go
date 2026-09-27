// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"errors"
	"net/http"
	"time"
)

// Option configures a [Client] during construction.
//
// The option receives private configuration, so callers should use the
// WithHTTPClient, WithBasicAuth, WithRequestTimeout,
// WithMaxResponseBodySize, and WithUserAgent functions supplied by this package.
// [NewClient] applies options in order and validates the resulting settings.
type Option func(*config) error

var (
	// ErrNilHTTPClient identifies a nil injected HTTP client.
	errNilHTTPClient = errors.New("HTTP client must not be nil")
	// ErrNonPositiveTimeout identifies a non-positive request timeout.
	errNonPositiveTimeout = errors.New("request timeout must be positive")
	// ErrNonPositiveLimit identifies a non-positive response body limit.
	errNonPositiveLimit = errors.New("maximum response body size must be positive")
)

// WithHTTPClient supplies the HTTP client used for requests.
//
// The selected client is shallow-copied by [NewClient]. Other settings, such as
// Transport, Jar, and Timeout, are preserved, but CheckRedirect is always
// replaced with the package redirect-rejection policy. The supplied client is
// not modified. Its Transport must satisfy the concurrency requirements of
// [http.RoundTripper]. When this option is omitted, the client uses a copy of
// [http.DefaultClient].
//
// Parameters:
//   - httpClient: The HTTP client to copy and use, or nil to reject
//     construction.
//
// Returns:
//   - An [Option] that selects the HTTP client.
func WithHTTPClient(httpClient *http.Client) Option {
	return func(cfg *config) error {
		if httpClient == nil {
			return configError(errNilHTTPClient)
		}

		cfg.httpClient = httpClient

		return nil
	}
}

// WithBasicAuth configures HTTP Basic authentication.
//
// When applied, every request includes the supplied username and password. The
// values are not validated and may be empty. Because the base URL must use HTTPS
// except on loopback hosts, credentials are not sent over plaintext transport to
// a remote server. Every redirect is rejected before a redirected request can
// be sent, so this client does not forward these credentials to redirect targets.
//
// Parameters:
//   - username: The HTTP Basic authentication username.
//   - password: The HTTP Basic authentication password.
//
// Returns:
//   - An [Option] that enables HTTP Basic authentication.
func WithBasicAuth(username, password string) Option {
	return func(cfg *config) error {
		cfg.basicAuth = true
		cfg.username = username
		cfg.password = password

		return nil
	}
}

// WithRequestTimeout sets the timeout applied to each request.
//
// The timeout must be positive; zero does not disable the bound. The default is
// 30 seconds. For each operation, the client derives a context with this
// timeout from the caller's context, so cancellation or an earlier caller
// deadline takes precedence. The derived context remains active while the
// response body is read and closed. A shorter Timeout on an injected
// [http.Client] may still end the operation earlier.
//
// Parameters:
//   - timeout: The positive per-request timeout.
//
// Returns:
//   - An [Option] that sets the request timeout.
func WithRequestTimeout(timeout time.Duration) Option {
	return func(cfg *config) error {
		if timeout <= 0 {
			return configError(errNonPositiveTimeout)
		}

		cfg.requestTimeout = timeout

		return nil
	}
}

// WithMaxResponseBodySize sets the maximum accepted response body size.
//
// The limit must be positive; the default is 1 MiB. A body whose size is
// exactly the limit is accepted. The client reads at most one probe byte beyond
// the limit and, when more data exists, closes the body and returns an
// [ErrorKindResponseTooLarge] error whose Limit field records this value. The
// bound is applied before response decoding or contract validation.
//
// Parameters:
//   - limit: The positive maximum response body size in bytes.
//
// Returns:
//   - An [Option] that sets the response body limit.
func WithMaxResponseBodySize(limit int64) Option {
	return func(cfg *config) error {
		if limit <= 0 {
			return configError(errNonPositiveLimit)
		}

		cfg.maxResponseBytes = limit

		return nil
	}
}

// WithUserAgent sets the User-Agent request header.
//
// The default is "agh-cli-adguard-client/1". [NewClient] rejects an empty value
// or any byte below 0x20 or equal to DEL (0x7f), preventing control characters
// from injecting header content.
//
// Parameters:
//   - userAgent: The complete User-Agent header value.
//
// Returns:
//   - An [Option] that sets the User-Agent header value.
func WithUserAgent(userAgent string) Option {
	return func(cfg *config) error {
		cfg.userAgent = userAgent

		return nil
	}
}
