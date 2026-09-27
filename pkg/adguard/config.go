// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// config contains normalized client construction settings.
type config struct {
	// baseURL is the validated absolute server URL and API path prefix.
	baseURL url.URL
	// httpClient is the HTTP client selected before it is cloned for redirects.
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

const (
	// The default request timeout is 30 seconds and bounds each complete request
	// and response-body read.
	defaultRequestTimeout = 30 * time.Second
	// The default maximum response size is 1 MiB.
	defaultMaxResponseBytes = 1 << 20
	// The default User-Agent value identifies this client.
	defaultUserAgent = "agh-cli-adguard-client/1"
)

var (
	// ErrNilOption identifies a nil functional option.
	errNilOption = errors.New("option must not be nil")
	// ErrInvalidBaseURLScheme identifies an unsupported URL scheme.
	errInvalidBaseURLScheme = errors.New("base URL scheme must be http or https")
	// ErrMissingBaseURLHost identifies a URL without a host.
	errMissingBaseURLHost = errors.New("base URL must include a host")
	// ErrInsecureBaseURL identifies plaintext HTTP for a non-loopback host.
	errInsecureBaseURL = errors.New("base URL must use HTTPS unless the host is loopback")
	// ErrBaseURLUserInfo identifies credentials embedded in a URL.
	errBaseURLUserInfo = errors.New("base URL must not include user information")
	// ErrBaseURLQuery identifies a base URL query.
	errBaseURLQuery = errors.New("base URL must not include a query")
	// ErrBaseURLFragment identifies a base URL fragment.
	errBaseURLFragment = errors.New("base URL must not include a fragment")
	// ErrOpaqueBaseURL identifies an opaque base URL.
	errOpaqueBaseURL = errors.New("base URL must not be opaque")
	// ErrEmptyUserAgent identifies an empty User-Agent value.
	errEmptyUserAgent = errors.New("user agent must not be empty")
	// ErrInvalidUserAgentHeader identifies a User-Agent control byte.
	errInvalidUserAgentHeader = errors.New("user agent contains an invalid byte")
)

// newConfig parses and validates client construction settings.
//
// The configuration starts with [http.DefaultClient], a 30-second request
// timeout, a 1 MiB response limit, and the package User-Agent. It validates the
// base URL before applying options in order, rejects a nil option, and validates
// the final User-Agent after all options run. Before returning, it shallow-copies
// the selected HTTP client and replaces CheckRedirect with [rejectRedirect], so
// neither the supplied client nor [http.DefaultClient] is modified.
//
// Parameters:
//   - baseURL: The absolute AdGuard Home server URL and optional API path prefix.
//   - options: The ordered functional options to apply.
//
// Returns:
//   - cfg: The normalized configuration when every check succeeds.
//   - err: A configuration error when the URL, an option, or the User-Agent is
//     invalid; otherwise nil.
func newConfig(baseURL string, options []Option) (*config, error) {
	var cfg config

	cfg.httpClient = http.DefaultClient
	cfg.requestTimeout = defaultRequestTimeout
	cfg.maxResponseBytes = defaultMaxResponseBytes
	cfg.userAgent = defaultUserAgent

	parsedURL, err := parseBaseURL(baseURL)
	if err != nil {
		return nil, configError(err)
	}

	cfg.baseURL = *parsedURL

	for _, option := range options {
		if option == nil {
			return nil, configError(errNilOption)
		}

		err = option(&cfg)
		if err != nil {
			return nil, fmt.Errorf("apply option: %w", err)
		}
	}

	err = validUserAgent(cfg.userAgent)
	if err != nil {
		return nil, configError(err)
	}

	httpClient := *cfg.httpClient

	httpClient.CheckRedirect = rejectRedirect
	cfg.httpClient = &httpClient

	return &cfg, nil
}

// parseBaseURL parses and normalizes a client base URL.
//
// The scheme is converted to lowercase before validation. Trailing slashes are
// removed from the path so it can be joined with relative control endpoints
// without changing the configured path prefix.
//
// Parameters:
//   - rawURL: The unparsed absolute AdGuard Home server URL.
//
// Returns:
//   - parsedURL: The normalized and validated base URL.
//   - err: A parsing or base-URL policy error; otherwise nil.
func parseBaseURL(rawURL string) (*url.URL, error) {
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}

	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)
	err = validateBaseURL(parsedURL)
	if err != nil {
		return nil, fmt.Errorf("validate base URL: %w", err)
	}

	parsedURL.Path = strings.TrimRight(parsedURL.Path, "/")

	return parsedURL, nil
}

// validateBaseURL enforces the supported URL policy.
//
// Authority validation runs before component validation so an insecure or
// malformed server address is reported before unrelated URL components.
//
// Parameters:
//   - parsedURL: The parsed base URL to validate.
//
// Returns:
//   - An authority or component policy error; otherwise nil.
func validateBaseURL(parsedURL *url.URL) error {
	err := validateBaseURLAuthority(parsedURL)
	if err != nil {
		return fmt.Errorf("validate base URL authority: %w", err)
	}

	err = validateBaseURLComponents(parsedURL)
	if err != nil {
		return fmt.Errorf("validate base URL components: %w", err)
	}

	return nil
}

// validateBaseURLAuthority enforces scheme, host, and transport security.
//
// Only normalized http and https schemes are accepted. HTTPS permits any
// non-empty host, while HTTP is restricted to localhost and loopback IP
// addresses so credentials and API data are not sent over plaintext transport
// to a remote server.
//
// Parameters:
//   - parsedURL: The parsed base URL whose scheme and authority to validate.
//
// Returns:
//   - An unsupported-scheme, missing-host, or insecure-transport error;
//     otherwise nil.
func validateBaseURLAuthority(parsedURL *url.URL) error {
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return errInvalidBaseURLScheme
	}
	if parsedURL.Host == "" {
		return errMissingBaseURLHost
	}
	if parsedURL.Scheme == "http" && !loopbackHost(parsedURL.Hostname()) {
		return errInsecureBaseURL
	}

	return nil
}

// validateBaseURLComponents rejects URL components that cannot identify a
// server.
//
// User information is rejected so credentials have one explicit authentication
// path. Queries, forced empty queries, fragments, and opaque forms are rejected
// so every operation resolves to one stable server path.
//
// Parameters:
//   - parsedURL: The parsed base URL whose components to validate.
//
// Returns:
//   - A user-information, query, fragment, or opaque-URL error; otherwise nil.
func validateBaseURLComponents(parsedURL *url.URL) error {
	switch {
	case parsedURL.User != nil:
		return errBaseURLUserInfo
	case parsedURL.RawQuery != "" || parsedURL.ForceQuery:
		return errBaseURLQuery
	case parsedURL.Fragment != "":
		return errBaseURLFragment
	case parsedURL.Opaque != "":
		return errOpaqueBaseURL
	default:
		return nil
	}
}

// loopbackHost reports whether a host identifies the local machine.
//
// The name localhost is accepted without case sensitivity. Other names must
// parse as IP addresses, and [net.IP.IsLoopback] must accept them; no DNS
// lookup is performed.
//
// Parameters:
//   - host: The hostname or IP address extracted from a base URL.
//
// Returns:
//   - Whether host is localhost or a loopback IP address.
func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}

	address := net.ParseIP(host)

	return address != nil && address.IsLoopback()
}

// validUserAgent rejects empty values and forbidden header bytes.
//
// Validation is byte-oriented. The value must be non-empty, and every byte must
// be at least 0x20, except that DEL (0x7f) is also rejected. This permits
// printable ASCII and HTTP obs-text bytes while preventing control characters
// from injecting additional header content.
//
// Parameters:
//   - userAgent: The complete User-Agent header value to validate.
//
// Returns:
//   - An empty-value or invalid-byte error; otherwise nil.
func validUserAgent(userAgent string) error {
	if userAgent == "" {
		return errEmptyUserAgent
	}

	for index := range len(userAgent) {
		if !validUserAgentByte(userAgent[index]) {
			return errInvalidUserAgentHeader
		}
	}

	return nil
}

// validUserAgentByte reports whether a byte is valid in a User-Agent value.
//
// Parameters:
//   - value: The byte to inspect.
//
// Returns:
//   - Whether value is at least 0x20 and is not DEL (0x7f).
func validUserAgentByte(value byte) bool {
	return value >= ' ' && value != 0x7f
}
