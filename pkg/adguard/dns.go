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
	"mime"
	"net/http"
	"strings"
)

// DNSService exposes DNS configuration and upstream testing.
type DNSService interface {
	DNSInfo(ctx context.Context) (*DNSConfig, error)
	SetDNSConfig(ctx context.Context, config *DNSConfig) error
	TestUpstreamDNS(ctx context.Context, config UpstreamConfig) (map[string]string, error)
}

// DNSConfig contains AdGuard Home's global DNS configuration.
//
// Optional slices use nil for an absent or null field and a nonnil empty slice
// for an explicitly empty list. Optional scalar fields use nil pointers for the
// same presence distinction, while nonnil pointers preserve explicit zero
// values. SetDNSConfig sends only present fields, except for the read-only
// DefaultLocalPTRUpstreams field.
type DNSConfig struct {
	// BootstrapDNS contains the optional bootstrap DNS server list.
	BootstrapDNS []string
	// UpstreamDNS contains the optional upstream DNS server list.
	UpstreamDNS []string
	// FallbackDNS contains the optional fallback DNS server list.
	FallbackDNS []string
	// UpstreamDNSFile optionally names a file containing upstream DNS servers.
	UpstreamDNSFile *string
	// ProtectionEnabled optionally controls whether DNS protection is enabled.
	ProtectionEnabled *bool
	// RateLimit optionally sets the DNS request rate limit.
	RateLimit *int64
	// RateLimitSubnetLengthIPv4 optionally sets the IPv4 rate-limit subnet length.
	RateLimitSubnetLengthIPv4 *int
	// RateLimitSubnetLengthIPv6 optionally sets the IPv6 rate-limit subnet length.
	RateLimitSubnetLengthIPv6 *int
	// RateLimitWhitelist contains the optional rate-limit allowlist.
	RateLimitWhitelist []string
	// BlockingMode optionally selects how blocked responses are generated.
	BlockingMode *string
	// BlockingIPv4 optionally contains the IPv4 address returned for blocked queries.
	BlockingIPv4 *string
	// BlockingIPv6 optionally contains the IPv6 address returned for blocked queries.
	BlockingIPv6 *string
	// BlockedResponseTTL optionally sets the blocked-response TTL in seconds.
	BlockedResponseTTL *int64
	// ProtectionDisabledUntil optionally contains the protection pause timestamp.
	ProtectionDisabledUntil *string
	// EDNSCSEnabled optionally controls EDNS client-subnet support.
	EDNSCSEnabled *bool
	// EDNSCSUseCustom optionally controls use of a custom EDNS client-subnet value.
	EDNSCSUseCustom *bool
	// EDNSCSCustomIP optionally contains the custom EDNS client-subnet value.
	EDNSCSCustomIP *string
	// DisableIPv6 optionally controls whether IPv6 processing is disabled.
	DisableIPv6 *bool
	// DNSSECEnabled optionally controls DNSSEC validation.
	DNSSECEnabled *bool
	// CacheSize optionally sets the DNS cache size.
	CacheSize *int64
	// CacheTTLMin optionally sets the minimum cache TTL in seconds.
	CacheTTLMin *int64
	// CacheTTLMax optionally sets the maximum cache TTL in seconds.
	CacheTTLMax *int64
	// CacheEnabled optionally controls whether DNS caching is enabled.
	CacheEnabled *bool
	// CacheOptimistic optionally enables optimistic DNS cache refresh.
	CacheOptimistic *bool
	// UpstreamMode optionally selects how upstream responses are selected.
	UpstreamMode *string
	// UsePrivatePTRResolvers optionally controls use of private PTR resolvers.
	UsePrivatePTRResolvers *bool
	// ResolveClients optionally controls local client-address resolution.
	ResolveClients *bool
	// LocalPTRUpstreams contains the optional local PTR upstream list.
	LocalPTRUpstreams []string
	// UpstreamTimeout optionally sets the upstream query timeout.
	UpstreamTimeout *int64
	// DefaultLocalPTRUpstreams contains the server's read-only default PTR upstreams.
	// SetDNSConfig ignores this field.
	DefaultLocalPTRUpstreams []string
}

// UpstreamConfig contains the upstream configuration to test.
//
// BootstrapDNS and UpstreamDNS are required and must be nonnil. Their nonnil
// empty values are sent as explicit empty lists. FallbackDNS and
// PrivateUpstream are optional, where nil omits the field and a nonnil empty
// slice sends an explicit empty list.
type UpstreamConfig struct {
	// BootstrapDNS contains the required bootstrap DNS server list.
	BootstrapDNS []string
	// UpstreamDNS contains the required upstream DNS server list.
	UpstreamDNS []string
	// FallbackDNS contains the optional fallback DNS server list.
	FallbackDNS []string
	// PrivateUpstream contains the optional private upstream DNS server list.
	PrivateUpstream []string
}

// optionalStrings distinguishes an absent list from an explicitly empty list.
type optionalStrings struct {
	values []string
}

// dnsConfigWire mirrors the pinned DNS configuration JSON contract.
type dnsConfigWire struct {
	BootstrapDNS              *optionalStrings `json:"bootstrap_dns,omitempty"`
	UpstreamDNS               *optionalStrings `json:"upstream_dns,omitempty"`
	FallbackDNS               *optionalStrings `json:"fallback_dns,omitempty"`
	UpstreamDNSFile           *string          `json:"upstream_dns_file,omitempty"`
	ProtectionEnabled         *bool            `json:"protection_enabled,omitempty"`
	RateLimit                 *int64           `json:"ratelimit,omitempty"`
	RateLimitSubnetLengthIPv4 *int             `json:"ratelimit_subnet_subnet_len_ipv4,omitempty"`
	RateLimitSubnetLengthIPv6 *int             `json:"ratelimit_subnet_subnet_len_ipv6,omitempty"`
	RateLimitWhitelist        *optionalStrings `json:"ratelimit_whitelist,omitempty"`
	BlockingMode              *string          `json:"blocking_mode,omitempty"`
	BlockingIPv4              *string          `json:"blocking_ipv4,omitempty"`
	BlockingIPv6              *string          `json:"blocking_ipv6,omitempty"`
	BlockedResponseTTL        *int64           `json:"blocked_response_ttl,omitempty"`
	ProtectionDisabledUntil   *string          `json:"protection_disabled_until,omitempty"`
	EDNSCSEnabled             *bool            `json:"edns_cs_enabled,omitempty"`
	EDNSCSUseCustom           *bool            `json:"edns_cs_use_custom,omitempty"`
	EDNSCSCustomIP            *string          `json:"edns_cs_custom_ip,omitempty"`
	DisableIPv6               *bool            `json:"disable_ipv6,omitempty"`
	DNSSECEnabled             *bool            `json:"dnssec_enabled,omitempty"`
	CacheSize                 *int64           `json:"cache_size,omitempty"`
	CacheTTLMin               *int64           `json:"cache_ttl_min,omitempty"`
	CacheTTLMax               *int64           `json:"cache_ttl_max,omitempty"`
	CacheEnabled              *bool            `json:"cache_enabled,omitempty"`
	CacheOptimistic           *bool            `json:"cache_optimistic,omitempty"`
	UpstreamMode              *string          `json:"upstream_mode,omitempty"`
	UsePrivatePTRResolvers    *bool            `json:"use_private_ptr_resolvers,omitempty"`
	ResolveClients            *bool            `json:"resolve_clients,omitempty"`
	LocalPTRUpstreams         *optionalStrings `json:"local_ptr_upstreams,omitempty"`
	UpstreamTimeout           *int64           `json:"upstream_timeout,omitempty"`
	DefaultLocalPTRUpstreams  *optionalStrings `json:"default_local_ptr_upstreams,omitempty"`
}

// upstreamConfigWire mirrors the pinned upstream test request contract.
type upstreamConfigWire struct {
	BootstrapDNS    []string         `json:"bootstrap_dns"`
	UpstreamDNS     []string         `json:"upstream_dns"`
	FallbackDNS     *optionalStrings `json:"fallback_dns,omitempty"`
	PrivateUpstream *optionalStrings `json:"private_upstream,omitempty"`
}

const (
	// OperationDNSInfo identifies DNS information retrieval.
	operationDNSInfo = "dns_info"
	// OperationDNSConfig identifies DNS configuration updates.
	operationDNSConfig = "dns_config"
	// OperationTestUpstream identifies upstream DNS tests.
	operationTestUpstream = "test_upstream_dns"
)

var (
	// ErrNilDNSConfig identifies a nil DNS configuration update.
	errNilDNSConfig = errors.New("DNS configuration must not be nil")
	// ErrRequiredUpstreamField identifies an absent required upstream field.
	errRequiredUpstreamField = errors.New("required upstream configuration field is missing")
	// ErrInvalidBlockingMode identifies an unsupported DNS blocking mode.
	errInvalidBlockingMode = errors.New("invalid DNS blocking mode")
	// ErrInvalidUpstreamMode identifies an unsupported DNS upstream mode.
	errInvalidUpstreamMode = errors.New("invalid DNS upstream mode")
	// ErrInvalidSubnetLength identifies an invalid rate-limit subnet length.
	errInvalidSubnetLength = errors.New("invalid DNS rate-limit subnet length")
	// ErrInvalidResponseTTL identifies a negative blocked response TTL.
	errInvalidResponseTTL = errors.New("blocked response TTL must not be negative")
	// ErrInvalidUpstreamTimeout identifies a non-positive upstream timeout.
	errInvalidUpstreamTimeout = errors.New("DNS upstream timeout must be positive")
)

var _ DNSService = (*Client)(nil)

// DNSInfo retrieves the global DNS configuration.
//
// Parameters:
//   - ctx: The request context.
//
// Returns:
//   - The global DNS configuration, or a client error when the request fails,
//     the response is not bounded JSON, or the response contains invalid values.
func (c *Client) DNSInfo(ctx context.Context) (*DNSConfig, error) {
	response, requestErr := c.get(ctx, operationDNSInfo, "control/dns_info")
	if requestErr != nil {
		return nil, requestErr
	}

	var wireConfig dnsConfigWire

	requestErr = decodeGlobalJSON(operationDNSInfo, http.MethodGet, response.body, &wireConfig)
	if requestErr != nil {
		return nil, requestErr
	}

	config := dnsConfigFromWire(wireConfig)

	err := validateDNSConfig(config)
	if err != nil {
		return nil, globalJSONError(operationDNSInfo, http.MethodGet, err)
	}

	return config, nil
}

// SetDNSConfig updates the global DNS configuration.
//
// Nil slices and scalar pointers omit their fields, while nonnil empty slices
// and pointers preserve explicit empty or zero values. The read-only
// DefaultLocalPTRUpstreams field is not sent.
//
// Parameters:
//   - ctx: The request context.
//   - config: The DNS configuration update. It must not be nil.
//
// Returns:
//   - An error when validation fails or the bounded request cannot be completed.
func (c *Client) SetDNSConfig(ctx context.Context, config *DNSConfig) error {
	if config == nil {
		return globalRequestError(operationDNSConfig, http.MethodPost, errNilDNSConfig)
	}

	err := validateDNSConfig(config)
	if err != nil {
		return globalRequestError(operationDNSConfig, http.MethodPost, err)
	}

	requestErr := c.postEmpty(
		ctx,
		operationDNSConfig,
		http.MethodPost,
		"control/dns_config",
		dnsConfigToWire(config),
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// TestUpstreamDNS tests an upstream DNS configuration.
//
// BootstrapDNS and UpstreamDNS must be nonnil, although either may be empty.
// Nil optional lists are omitted, while nonnil empty lists are sent explicitly.
// Per-upstream failures are returned as entries in the result map rather than as
// a method error.
//
// Parameters:
//   - ctx: The request context.
//   - config: The upstream configuration to test.
//
// Returns:
//   - A map from upstream address to its reported result, or a client error when
//     validation, transport, response validation, or JSON decoding fails.
func (c *Client) TestUpstreamDNS(
	ctx context.Context,
	config UpstreamConfig,
) (map[string]string, error) {
	if config.BootstrapDNS == nil || config.UpstreamDNS == nil {
		return nil, globalRequestError(
			operationTestUpstream,
			http.MethodPost,
			errRequiredUpstreamField,
		)
	}

	results := map[string]string{}
	requestErr := c.postJSON(
		ctx,
		operationTestUpstream,
		http.MethodPost,
		"control/test_upstream_dns",
		upstreamConfigWire{
			BootstrapDNS:    config.BootstrapDNS,
			UpstreamDNS:     config.UpstreamDNS,
			FallbackDNS:     slicePointer(config.FallbackDNS),
			PrivateUpstream: slicePointer(config.PrivateUpstream),
		},
		&results,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	return results, nil
}

// IsZero prevents an explicitly present empty list from being omitted.
//
// Returns:
//   - Always false so a nonnil wrapper remains present during JSON encoding.
func (*optionalStrings) IsZero() bool {
	return false
}

// UnmarshalJSON decodes an optional string list.
//
// Parameters:
//   - o: The optional string list to populate.
//   - data: The JSON list to decode.
//
// Returns:
//   - An error when data is not a valid JSON string list.
func (o *optionalStrings) UnmarshalJSON(data []byte) error {
	err := json.Unmarshal(data, &o.values)
	if err != nil {
		return fmt.Errorf("unmarshal optional string list: %w", err)
	}

	return nil
}

// MarshalJSON emits only fields present in the DNS configuration request.
//
// Parameters:
//   - dc: The DNS configuration wire representation to encode.
//
// Returns:
//   - The encoded JSON object, or an error when it cannot be encoded.
func (dc dnsConfigWire) MarshalJSON() ([]byte, error) {
	payload := make(map[string]any, 31)
	addDNSListFields(payload, dc)
	addDNSNetworkFields(payload, dc)
	addDNSBlockingFields(payload, dc)
	addDNSCacheFields(payload, dc)
	addDNSExtensionFields(payload, dc)
	addDNSResolverFields(payload, dc)

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal DNS configuration: %w", err)
	}

	return payloadBytes, nil
}

// MarshalJSON emits required upstream fields and present optional lists.
//
// Parameters:
//   - uc: The upstream configuration wire representation to encode.
//
// Returns:
//   - The encoded JSON object, or an error when it cannot be encoded.
func (uc upstreamConfigWire) MarshalJSON() ([]byte, error) {
	payload := map[string]any{
		"bootstrap_dns": uc.BootstrapDNS,
		"upstream_dns":  uc.UpstreamDNS,
	}
	if uc.FallbackDNS != nil {
		payload["fallback_dns"] = uc.FallbackDNS.values
	}
	if uc.PrivateUpstream != nil {
		payload["private_upstream"] = uc.PrivateUpstream.values
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal upstream configuration: %w", err)
	}

	return payloadBytes, nil
}

// addDNSListFields adds present DNS list fields to a request payload.
//
// Parameters:
//   - payload: The JSON object being assembled.
//   - wireConfig: The DNS configuration whose present lists should be copied.
//
// Returns:
//   - Nothing; the function updates payload in place.
func addDNSListFields(payload map[string]any, wireConfig dnsConfigWire) {
	if wireConfig.BootstrapDNS != nil {
		payload["bootstrap_dns"] = wireConfig.BootstrapDNS.values
	}
	if wireConfig.UpstreamDNS != nil {
		payload["upstream_dns"] = wireConfig.UpstreamDNS.values
	}
	if wireConfig.FallbackDNS != nil {
		payload["fallback_dns"] = wireConfig.FallbackDNS.values
	}
	if wireConfig.RateLimitWhitelist != nil {
		payload["ratelimit_whitelist"] = wireConfig.RateLimitWhitelist.values
	}
}

// addDNSNetworkFields adds present DNS network fields to a request payload.
//
// Parameters:
//   - payload: The JSON object being assembled.
//   - wireConfig: The DNS configuration whose present network fields should be copied.
//
// Returns:
//   - Nothing; the function updates payload in place.
func addDNSNetworkFields(payload map[string]any, wireConfig dnsConfigWire) {
	if wireConfig.UpstreamDNSFile != nil {
		payload["upstream_dns_file"] = wireConfig.UpstreamDNSFile
	}
	if wireConfig.ProtectionEnabled != nil {
		payload["protection_enabled"] = wireConfig.ProtectionEnabled
	}
	if wireConfig.RateLimit != nil {
		payload["ratelimit"] = wireConfig.RateLimit
	}
	if wireConfig.RateLimitSubnetLengthIPv4 != nil {
		payload["ratelimit_subnet_subnet_len_ipv4"] = wireConfig.RateLimitSubnetLengthIPv4
	}
	if wireConfig.RateLimitSubnetLengthIPv6 != nil {
		payload["ratelimit_subnet_subnet_len_ipv6"] = wireConfig.RateLimitSubnetLengthIPv6
	}
}

// addDNSBlockingFields adds present DNS blocking fields to a request payload.
//
// Parameters:
//   - payload: The JSON object being assembled.
//   - wireConfig: The DNS configuration whose present blocking fields should be copied.
//
// Returns:
//   - Nothing; the function updates payload in place.
func addDNSBlockingFields(payload map[string]any, wireConfig dnsConfigWire) {
	if wireConfig.BlockingMode != nil {
		payload["blocking_mode"] = wireConfig.BlockingMode
	}
	if wireConfig.BlockingIPv4 != nil {
		payload["blocking_ipv4"] = wireConfig.BlockingIPv4
	}
	if wireConfig.BlockingIPv6 != nil {
		payload["blocking_ipv6"] = wireConfig.BlockingIPv6
	}
}

// addDNSCacheFields adds present DNS cache fields to a request payload.
//
// Parameters:
//   - payload: The JSON object being assembled.
//   - wireConfig: The DNS configuration whose present cache fields should be copied.
//
// Returns:
//   - Nothing; the function updates payload in place.
func addDNSCacheFields(payload map[string]any, wireConfig dnsConfigWire) {
	if wireConfig.BlockedResponseTTL != nil {
		payload["blocked_response_ttl"] = wireConfig.BlockedResponseTTL
	}
	if wireConfig.ProtectionDisabledUntil != nil {
		payload["protection_disabled_until"] = wireConfig.ProtectionDisabledUntil
	}
	if wireConfig.CacheSize != nil {
		payload["cache_size"] = wireConfig.CacheSize
	}
	if wireConfig.CacheTTLMin != nil {
		payload["cache_ttl_min"] = wireConfig.CacheTTLMin
	}
	if wireConfig.CacheTTLMax != nil {
		payload["cache_ttl_max"] = wireConfig.CacheTTLMax
	}
	if wireConfig.CacheEnabled != nil {
		payload["cache_enabled"] = wireConfig.CacheEnabled
	}
	if wireConfig.CacheOptimistic != nil {
		payload["cache_optimistic"] = wireConfig.CacheOptimistic
	}
}

// addDNSExtensionFields adds present DNS extension fields to a request payload.
//
// Parameters:
//   - payload: The JSON object being assembled.
//   - wireConfig: The DNS configuration whose present extension fields should be copied.
//
// Returns:
//   - Nothing; the function updates payload in place.
func addDNSExtensionFields(payload map[string]any, wireConfig dnsConfigWire) {
	if wireConfig.EDNSCSEnabled != nil {
		payload["edns_cs_enabled"] = wireConfig.EDNSCSEnabled
	}
	if wireConfig.EDNSCSUseCustom != nil {
		payload["edns_cs_use_custom"] = wireConfig.EDNSCSUseCustom
	}
	if wireConfig.EDNSCSCustomIP != nil {
		payload["edns_cs_custom_ip"] = wireConfig.EDNSCSCustomIP
	}
	if wireConfig.DisableIPv6 != nil {
		payload["disable_ipv6"] = wireConfig.DisableIPv6
	}
	if wireConfig.DNSSECEnabled != nil {
		payload["dnssec_enabled"] = wireConfig.DNSSECEnabled
	}
}

// addDNSResolverFields adds present DNS resolver fields to a request payload.
//
// Parameters:
//   - payload: The JSON object being assembled.
//   - wireConfig: The DNS configuration whose present resolver fields should be copied.
//
// Returns:
//   - Nothing; the function updates payload in place.
func addDNSResolverFields(payload map[string]any, wireConfig dnsConfigWire) {
	if wireConfig.UpstreamMode != nil {
		payload["upstream_mode"] = wireConfig.UpstreamMode
	}
	if wireConfig.UsePrivatePTRResolvers != nil {
		payload["use_private_ptr_resolvers"] = wireConfig.UsePrivatePTRResolvers
	}
	if wireConfig.ResolveClients != nil {
		payload["resolve_clients"] = wireConfig.ResolveClients
	}
	if wireConfig.LocalPTRUpstreams != nil {
		payload["local_ptr_upstreams"] = wireConfig.LocalPTRUpstreams.values
	}
	if wireConfig.UpstreamTimeout != nil {
		payload["upstream_timeout"] = wireConfig.UpstreamTimeout
	}
}

// postNoContent sends a bodyless POST and accepts a bounded successful response.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The operation identifier used in errors.
//   - endpoint: The endpoint path relative to the configured base URL.
//
// Returns:
//   - A client error when request execution, bounded reading, closing, or
//     response status validation fails.
func (c *Client) postNoContent(ctx context.Context, operation, endpoint string) *Error {
	response, cancel, requestErr := c.executeGlobalRequest(
		ctx,
		operation,
		http.MethodPost,
		endpoint,
		http.NoBody,
	)
	if requestErr != nil {
		return requestErr
	}

	_, requestErr = readGlobalResponse(operation, http.MethodPost, response, c.maxResponseBytes)

	cancel()

	return requestErr
}

// postEmpty sends a JSON request and accepts a bounded bodyless successful response.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used for the request.
//   - endpoint: The endpoint path relative to the configured base URL.
//   - body: The value to encode as the JSON request body.
//
// Returns:
//   - A client error when encoding, request execution, bounded reading, closing,
//     or response status validation fails.
func (c *Client) postEmpty(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	body any,
) *Error {
	payload, err := json.Marshal(body)
	if err != nil {
		return globalRequestError(operation, method, fmt.Errorf("encode request: %w", err))
	}

	response, cancel, requestErr := c.executeGlobalRequest(
		ctx,
		operation,
		method,
		endpoint,
		bytes.NewReader(payload),
	)
	if requestErr != nil {
		return requestErr
	}

	_, requestErr = readGlobalResponse(operation, method, response, c.maxResponseBytes)

	cancel()

	return requestErr
}

// postJSON sends a JSON request and decodes its bounded JSON response.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The operation identifier used in errors.
//   - method: The legacy method argument, which this POST helper ignores.
//   - endpoint: The endpoint path relative to the configured base URL.
//   - body: The value to encode as the JSON request body.
//   - result: The destination for the decoded JSON response.
//
// Returns:
//   - A client error when encoding, request execution, bounded reading, closing,
//     response status, media type, or JSON decoding fails.
func (c *Client) postJSON(
	ctx context.Context,
	operation string,
	_ string,
	endpoint string,
	body any,
	result any,
) *Error {
	const method = http.MethodPost

	payload, err := json.Marshal(body)
	if err != nil {
		return globalRequestError(operation, method, fmt.Errorf("encode request: %w", err))
	}

	response, cancel, requestErr := c.executeGlobalRequest( //nolint:bodyclose // readGlobalResponse closes the body.
		ctx,
		operation,
		method,
		endpoint,
		bytes.NewReader(payload),
	)
	if requestErr != nil {
		return requestErr
	}

	requestErr = readGlobalJSONResponse(
		operation,
		method,
		response,
		c.maxResponseBytes,
		result,
	)

	cancel()

	return requestErr
}

// executeGlobalRequest sends a request and returns its response and cancellation function.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used for the request.
//   - endpoint: The endpoint path relative to the configured base URL.
//   - body: The request body, or nil for no body.
//
// Returns:
//   - The HTTP response and a function that releases the request context, or a
//     client error when request construction or execution fails.
func (c *Client) executeGlobalRequest(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	body io.Reader,
) (*http.Response, context.CancelFunc, *Error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newGlobalRequest(requestContext, operation, method, endpoint, body)
	if requestErr != nil {
		cancel()

		return nil, nil, requestErr
	}

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		cancel()

		requestErr.Method = method

		return nil, nil, requestErr
	}

	return response, cancel, nil
}

// newGlobalRequest creates a global endpoint request with standard headers.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used for the request.
//   - endpoint: The endpoint path relative to the configured base URL.
//   - body: The request body, or nil for no body.
//
// Returns:
//   - The prepared request, or a client error when the request cannot be created.
func (c *Client) newGlobalRequest(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	body io.Reader,
) (*http.Request, *Error) {
	requestURL := c.endpoint(endpoint)
	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return nil, globalRequestError(operation, method, fmt.Errorf("%w: %w", errCreateRequest, err))
	}

	request.Header.Set("Accept", jsonContentType)
	request.Header.Set("User-Agent", c.userAgent)

	if body != nil && body != http.NoBody {
		request.Header.Set("Content-Type", jsonContentType)
	}
	if c.basicAuth {
		request.SetBasicAuth(c.username, c.password)
	}

	return request, nil
}

// readGlobalResponse reads, bounds, closes, and validates a global response.
//
// Parameters:
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used in errors.
//   - response: The HTTP response to consume and close.
//   - limit: The maximum response body size in bytes.
//
// Returns:
//   - The bounded response body, or a client error when reading, closing, or
//     response status validation fails.
func readGlobalResponse(
	operation string,
	method string,
	response *http.Response,
	limit int64,
) ([]byte, *Error) {
	body, tooLarge, readErr := readBounded(response.Body, limit)
	closeErr := response.Body.Close()

	requestErr := globalBodyError(operation, method, response, limit, tooLarge, readErr, closeErr)
	if requestErr != nil {
		return nil, requestErr
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, statusError(
			operation,
			method,
			response.StatusCode,
			response.Status,
			response.Header.Get("Content-Type"),
			body,
		)
	}

	return body, nil
}

// readGlobalJSONResponse validates JSON media type and decodes a successful response.
//
// Parameters:
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used in errors.
//   - response: The HTTP response to consume and close.
//   - limit: The maximum response body size in bytes.
//   - result: The destination for the decoded JSON response.
//
// Returns:
//   - A client error when bounded reading, closing, response status, media type,
//     or JSON decoding fails.
func readGlobalJSONResponse(
	operation string,
	method string,
	response *http.Response,
	limit int64,
	result any,
) *Error {
	body, requestErr := readGlobalResponse(operation, method, response, limit)
	if requestErr != nil {
		return requestErr
	}

	requestErr = validateGlobalJSONContentType(operation, method, response)
	if requestErr != nil {
		return requestErr
	}

	return decodeGlobalJSON(operation, method, body, result)
}

// globalBodyError classifies bounded response-body failures.
//
// Parameters:
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used in errors.
//   - response: The HTTP response being consumed.
//   - limit: The maximum response body size in bytes.
//   - tooLarge: Whether the body exceeded the limit.
//   - readErr: The body read error, if any.
//   - closeErr: The body close error, if any.
//
// Returns:
//   - The classified client error, or nil when bounded reading and closing succeed.
func globalBodyError(
	operation string,
	method string,
	response *http.Response,
	limit int64,
	tooLarge bool,
	readErr error,
	closeErr error,
) *Error {
	switch {
	case tooLarge:
		requestErr := responseError(operation, ErrorKindResponseTooLarge, response, nil)

		requestErr.Method = method
		requestErr.Limit = limit

		return requestErr
	case readErr != nil:
		return globalResponseBodyError(
			operation,
			method,
			response,
			fmt.Errorf("%w: %w", errReadResponse, readErr),
		)
	case closeErr != nil:
		return globalResponseBodyError(
			operation,
			method,
			response,
			fmt.Errorf("%w: %w", errCloseResponse, closeErr),
		)
	default:
		return nil
	}
}

// globalResponseBodyError creates a response-body error with the correct method.
//
// Parameters:
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used in errors.
//   - response: The HTTP response being consumed.
//   - cause: The underlying body read or close error.
//
// Returns:
//   - The classified response-body client error.
func globalResponseBodyError(
	operation string,
	method string,
	response *http.Response,
	cause error,
) *Error {
	requestErr := responseError(operation, ErrorKindResponseBody, response, cause)

	requestErr.Method = method

	return requestErr
}

// validateGlobalJSONContentType enforces JSON media type on a successful response.
//
// Parameters:
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used in errors.
//   - response: The successful HTTP response to inspect.
//
// Returns:
//   - A content-type client error, or nil when the media type is JSON.
func validateGlobalJSONContentType(operation, method string, response *http.Response) *Error {
	contentType := response.Header.Get("Content-Type")

	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		requestErr := responseError(
			operation,
			ErrorKindContentType,
			response,
			fmt.Errorf("%w: %w", errParseContentType, err),
		)

		requestErr.Method = method

		return requestErr
	}
	if !strings.EqualFold(mediaType, jsonContentType) {
		requestErr := responseError(
			operation,
			ErrorKindContentType,
			response,
			fmt.Errorf("%w: %s", errUnexpectedJSONType, mediaType),
		)

		requestErr.Method = method

		return requestErr
	}

	return nil
}

// decodeGlobalJSON strictly decodes a JSON response.
//
// Parameters:
//   - operation: The operation identifier used in errors.
//   - method: The HTTP method used in errors.
//   - body: The bounded JSON response body.
//   - result: The destination for the decoded response.
//
// Returns:
//   - A JSON client error when the body is top-level null or cannot be decoded.
func decodeGlobalJSON(operation, method string, body []byte, result any) *Error {
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return globalJSONError(operation, method, errNullJSONResponse)
	}

	err := json.Unmarshal(body, result)
	if err != nil {
		return globalJSONError(operation, method, fmt.Errorf("decode response: %w", err))
	}

	return nil
}

// globalJSONError creates a structured JSON decoding error.
//
// Parameters:
//   - operation: The operation identifier for the error.
//   - method: The HTTP method for the error.
//   - err: The underlying decoding or validation error.
//
// Returns:
//   - The structured JSON client error.
func globalJSONError(operation, method string, err error) *Error {
	requestErr := newError(ErrorKindJSON)

	requestErr.Operation = operation
	requestErr.Method = method
	requestErr.Err = err

	return requestErr
}

// globalRequestError creates a structured request error.
//
// Parameters:
//   - operation: The operation identifier for the error.
//   - method: The HTTP method for the error.
//   - err: The underlying request validation error.
//
// Returns:
//   - The structured request client error.
func globalRequestError(operation, method string, err error) *Error {
	requestErr := newError(ErrorKindRequest)

	requestErr.Operation = operation
	requestErr.Method = method
	requestErr.Err = err

	return requestErr
}

// dnsConfigFromWire converts a wire DNS configuration to the domain model.
//
// Parameters:
//   - wireConfig: The decoded wire representation.
//
// Returns:
//   - The domain DNS configuration with optional presence preserved.
func dnsConfigFromWire(wireConfig dnsConfigWire) *DNSConfig {
	return &DNSConfig{
		BootstrapDNS:              valueFromSlicePointer(wireConfig.BootstrapDNS),
		UpstreamDNS:               valueFromSlicePointer(wireConfig.UpstreamDNS),
		FallbackDNS:               valueFromSlicePointer(wireConfig.FallbackDNS),
		UpstreamDNSFile:           wireConfig.UpstreamDNSFile,
		ProtectionEnabled:         wireConfig.ProtectionEnabled,
		RateLimit:                 wireConfig.RateLimit,
		RateLimitSubnetLengthIPv4: wireConfig.RateLimitSubnetLengthIPv4,
		RateLimitSubnetLengthIPv6: wireConfig.RateLimitSubnetLengthIPv6,
		RateLimitWhitelist:        valueFromSlicePointer(wireConfig.RateLimitWhitelist),
		BlockingMode:              wireConfig.BlockingMode,
		BlockingIPv4:              wireConfig.BlockingIPv4,
		BlockingIPv6:              wireConfig.BlockingIPv6,
		BlockedResponseTTL:        wireConfig.BlockedResponseTTL,
		ProtectionDisabledUntil:   wireConfig.ProtectionDisabledUntil,
		EDNSCSEnabled:             wireConfig.EDNSCSEnabled,
		EDNSCSUseCustom:           wireConfig.EDNSCSUseCustom,
		EDNSCSCustomIP:            wireConfig.EDNSCSCustomIP,
		DisableIPv6:               wireConfig.DisableIPv6,
		DNSSECEnabled:             wireConfig.DNSSECEnabled,
		CacheSize:                 wireConfig.CacheSize,
		CacheTTLMin:               wireConfig.CacheTTLMin,
		CacheTTLMax:               wireConfig.CacheTTLMax,
		CacheEnabled:              wireConfig.CacheEnabled,
		CacheOptimistic:           wireConfig.CacheOptimistic,
		UpstreamMode:              wireConfig.UpstreamMode,
		UsePrivatePTRResolvers:    wireConfig.UsePrivatePTRResolvers,
		ResolveClients:            wireConfig.ResolveClients,
		LocalPTRUpstreams:         valueFromSlicePointer(wireConfig.LocalPTRUpstreams),
		UpstreamTimeout:           wireConfig.UpstreamTimeout,
		DefaultLocalPTRUpstreams:  valueFromSlicePointer(wireConfig.DefaultLocalPTRUpstreams),
	}
}

// dnsConfigToWire converts the domain DNS configuration to its request wire form.
//
// Parameters:
//   - config: The domain DNS configuration to convert.
//
// Returns:
//   - The wire representation with optional list presence preserved and the
//     read-only default PTR list omitted.
func dnsConfigToWire(config *DNSConfig) dnsConfigWire {
	return dnsConfigWire{
		BootstrapDNS:              slicePointer(config.BootstrapDNS),
		UpstreamDNS:               slicePointer(config.UpstreamDNS),
		FallbackDNS:               slicePointer(config.FallbackDNS),
		UpstreamDNSFile:           config.UpstreamDNSFile,
		ProtectionEnabled:         config.ProtectionEnabled,
		RateLimit:                 config.RateLimit,
		RateLimitSubnetLengthIPv4: config.RateLimitSubnetLengthIPv4,
		RateLimitSubnetLengthIPv6: config.RateLimitSubnetLengthIPv6,
		RateLimitWhitelist:        slicePointer(config.RateLimitWhitelist),
		BlockingMode:              config.BlockingMode,
		BlockingIPv4:              config.BlockingIPv4,
		BlockingIPv6:              config.BlockingIPv6,
		BlockedResponseTTL:        config.BlockedResponseTTL,
		ProtectionDisabledUntil:   config.ProtectionDisabledUntil,
		EDNSCSEnabled:             config.EDNSCSEnabled,
		EDNSCSUseCustom:           config.EDNSCSUseCustom,
		EDNSCSCustomIP:            config.EDNSCSCustomIP,
		DisableIPv6:               config.DisableIPv6,
		DNSSECEnabled:             config.DNSSECEnabled,
		CacheSize:                 config.CacheSize,
		CacheTTLMin:               config.CacheTTLMin,
		CacheTTLMax:               config.CacheTTLMax,
		CacheEnabled:              config.CacheEnabled,
		CacheOptimistic:           config.CacheOptimistic,
		UpstreamMode:              config.UpstreamMode,
		UsePrivatePTRResolvers:    config.UsePrivatePTRResolvers,
		ResolveClients:            config.ResolveClients,
		LocalPTRUpstreams:         slicePointer(config.LocalPTRUpstreams),
		UpstreamTimeout:           config.UpstreamTimeout,
		DefaultLocalPTRUpstreams:  nil,
	}
}

// validateDNSConfig enforces the DNS configuration schema constraints.
//
// Parameters:
//   - config: The DNS configuration to validate.
//
// Returns:
//   - An error when a numeric bound, blocking mode, or upstream mode is invalid.
func validateDNSConfig(config *DNSConfig) error {
	err := validateDNSConfigBounds(config)
	if err != nil {
		return fmt.Errorf("validate DNS configuration bounds: %w", err)
	}

	err = validateDNSBlockingMode(config.BlockingMode)
	if err != nil {
		return fmt.Errorf("validate DNS blocking mode: %w", err)
	}

	err = validateDNSUpstreamMode(config.UpstreamMode)
	if err != nil {
		return fmt.Errorf("validate DNS upstream mode: %w", err)
	}

	return nil
}

// validateDNSConfigBounds enforces bounded numeric DNS configuration fields.
//
// Parameters:
//   - config: The DNS configuration to validate.
//
// Returns:
//   - An error when a present numeric value is outside its allowed bounds.
func validateDNSConfigBounds(config *DNSConfig) error {
	err := validateRateLimitSubnets(config)
	if err != nil {
		return fmt.Errorf("validate rate-limit subnets: %w", err)
	}
	if config.BlockedResponseTTL != nil && *config.BlockedResponseTTL < 0 {
		return errInvalidResponseTTL
	}
	if config.UpstreamTimeout != nil && *config.UpstreamTimeout < 1 {
		return errInvalidUpstreamTimeout
	}

	return nil
}

// validateRateLimitSubnets enforces IPv4 and IPv6 rate-limit subnet bounds.
//
// Parameters:
//   - config: The DNS configuration to validate.
//
// Returns:
//   - An error when a present subnet length is outside its address-family bound.
func validateRateLimitSubnets(config *DNSConfig) error {
	ipv4Length := config.RateLimitSubnetLengthIPv4
	if ipv4Length != nil && (*ipv4Length < 0 || *ipv4Length > 32) {
		return errInvalidSubnetLength
	}

	ipv6Length := config.RateLimitSubnetLengthIPv6
	if ipv6Length != nil && (*ipv6Length < 0 || *ipv6Length > 128) {
		return errInvalidSubnetLength
	}

	return nil
}

// validateDNSBlockingMode enforces the pinned blocking-mode enumeration.
//
// Parameters:
//   - mode: The optional blocking mode to validate.
//
// Returns:
//   - An error when a present mode is unsupported.
func validateDNSBlockingMode(mode *string) error {
	if mode == nil {
		return nil
	}

	switch *mode {
	case "default", "refused", "nxdomain", "null_ip", "custom_ip":
		return nil
	default:
		return errInvalidBlockingMode
	}
}

// validateDNSUpstreamMode enforces the pinned upstream-mode enumeration.
//
// Parameters:
//   - mode: The optional upstream mode to validate.
//
// Returns:
//   - An error when a present mode is unsupported.
func validateDNSUpstreamMode(mode *string) error {
	if mode == nil {
		return nil
	}

	switch *mode {
	case "", "fastest_addr", "load_balance", "parallel":
		return nil
	default:
		return errInvalidUpstreamMode
	}
}

// slicePointer returns an optional wire list while preserving empty slices.
//
// Parameters:
//   - values: The domain list whose presence should be preserved.
//
// Returns:
//   - Nil for a nil list, or a nonnil wire wrapper for a present list.
func slicePointer(values []string) *optionalStrings {
	if values == nil {
		return nil
	}

	return &optionalStrings{values: values}
}

// valueFromSlicePointer returns the domain value represented by an optional wire list.
//
// Parameters:
//   - values: The optional wire list to unwrap.
//
// Returns:
//   - Nil for an absent list, or the decoded slice for a present list.
func valueFromSlicePointer(values *optionalStrings) []string {
	if values == nil {
		return nil
	}

	return values.values
}
