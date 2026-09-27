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

// ServerService exposes server-level status and protection controls.
type ServerService interface {
	Status(ctx context.Context) (*ServerStatus, error)
	SetProtection(ctx context.Context, config ProtectionConfig) error
	ClearCache(ctx context.Context) error
}

// ServerStatus is the AdGuard Home server status returned by GET
// /control/status.
//
// DNSAddresses, DNSPort, HTTPPort, Language, ProtectionEnabled, Running, and
// Version are required by the response contract. ProtectionDisabledDuration,
// DHCPAvailable, and StartTime are optional: nil means that the server omitted
// the field or returned JSON null. Unknown response members are ignored.
type ServerStatus struct {
	// DNSAddresses contains the addresses served by AdGuard Home. An empty,
	// non-nil slice means that the server returned an empty list.
	DNSAddresses []string
	// DNSPort is the required DNS listening port and must be non-zero.
	DNSPort uint16
	// HTTPPort is the required web-interface listening port and must be non-zero.
	HTTPPort uint16
	// Language is the required configured web-interface language.
	Language string
	// ProtectionEnabled reports whether filtering protection is enabled.
	ProtectionEnabled bool
	// ProtectionDisabledDuration is the remaining disabled-protection duration
	// reported by the server, or nil when the optional value is absent or null.
	ProtectionDisabledDuration *int64
	// DHCPAvailable reports whether the DHCP service is available, or is nil when
	// the optional value is absent or null.
	DHCPAvailable *bool
	// Running reports whether the AdGuard Home server is running.
	Running bool
	// Version is the required AdGuard Home version.
	Version string
	// StartTime is the optional web API server start time in Unix milliseconds,
	// or nil when the value is absent or null.
	StartTime *float64
}

// serverStatusResponse mirrors the pinned status response schema.
//
// Pointer fields preserve the difference between an absent or null value and a
// present false, zero, or empty value. Validation converts the required fields
// into the public value model and retains optional pointers directly.
type serverStatusResponse struct {
	// DNSAddresses is nil when the required list is absent or null.
	DNSAddresses *[]string `json:"dns_addresses"`
	// DNSPort is nil when the required port is absent or null.
	DNSPort *uint16 `json:"dns_port"`
	// HTTPPort is nil when the required port is absent or null.
	HTTPPort *uint16 `json:"http_port"`
	// Language is nil when the required language is absent or null.
	Language *string `json:"language"`
	// ProtectionEnabled is nil when the required state is absent or null.
	ProtectionEnabled *bool `json:"protection_enabled"`
	// ProtectionDisabledDuration is nil when the optional duration is absent or
	// null.
	ProtectionDisabledDuration *int64 `json:"protection_disabled_duration"`
	// DHCPAvailable is nil when the optional DHCP state is absent or null.
	DHCPAvailable *bool `json:"dhcp_available"`
	// Running is nil when the required running state is absent or null.
	Running *bool `json:"running"`
	// Version is nil when the required version is absent or null.
	Version *string `json:"version"`
	// StartTime is nil when the optional start time is absent or null.
	StartTime *float64 `json:"start_time"`
}

var (
	// ErrRequiredStatusField identifies an absent required response field.
	errRequiredStatusField = errors.New("required status field is missing")
	// ErrInvalidDNSPort identifies a DNS port outside the contract range.
	errInvalidDNSPort = errors.New("dns_port must be between 1 and 65535")
	// ErrInvalidHTTPPort identifies an HTTP port outside the contract range.
	errInvalidHTTPPort = errors.New("http_port must be between 1 and 65535")
)

var _ ServerService = (*Client)(nil)

// Status retrieves the current AdGuard Home server status.
//
// Status sends GET /control/status below the configured base URL path, using
// the configured User-Agent and optional HTTP Basic credentials. The caller's
// context controls cancellation; the effective deadline is the earlier of that
// context and the configured request timeout. Redirects are rejected, the
// response body is bounded by [WithMaxResponseBodySize], and every body is
// closed. A successful response must have a 2xx status and an application/json
// media type. Unknown JSON members are ignored, required members must be
// present, and both required ports must be non-zero.
//
// Parameters:
//   - ctx: The parent request context. Cancellation or an earlier deadline stops
//     the operation.
//
// Returns:
//   - status: The decoded and validated server status.
//   - err: An [Error] for request, redirect, HTTP-status, response-limit,
//     response-body, media-type, JSON, required-field, or invalid-port failures;
//     otherwise nil.
//
// Example:
//
//	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
//	defer cancel()
//
//	status, err := client.Status(ctx)
//	if err != nil {
//		if clientErr, ok := errors.AsType[*Error](err); ok {
//			fmt.Println(clientErr.Kind)
//		}
//
//		return err
//	}
//
//	fmt.Println(status.Version)
func (c *Client) Status(ctx context.Context) (*ServerStatus, error) {
	operation := string(ErrorKindStatus)
	response, requestErr := c.get(ctx, operation, "control/status")
	if requestErr != nil {
		return nil, requestErr
	}

	status, decodeErr := decodeServerStatus(response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return status, nil
}

// decodeServerStatus strictly decodes and validates a status response.
//
// Decoding preserves field presence, rejects malformed or duplicate JSON, and
// ignores unknown members. The wire response is validated before required
// pointers are dereferenced. Any decoding or schema error is returned as
// [ErrorKindJSON].
//
// Parameters:
//   - body: The already bounded JSON response body.
//
// Returns:
//   - status: The public status when decoding and validation succeed.
//   - err: An [Error] with [ErrorKindJSON] for decoding or contract failures;
//     otherwise nil.
func decodeServerStatus(body []byte) (*ServerStatus, *Error) {
	var wireStatus serverStatusResponse

	err := json.Unmarshal(body, &wireStatus)
	if err != nil {
		return nil, jsonError(fmt.Errorf("decode response: %w", err))
	}

	err = validateServerStatus(wireStatus)
	if err != nil {
		return nil, jsonError(err)
	}

	return &ServerStatus{
		DNSAddresses:               *wireStatus.DNSAddresses,
		DNSPort:                    *wireStatus.DNSPort,
		HTTPPort:                   *wireStatus.HTTPPort,
		Language:                   *wireStatus.Language,
		ProtectionEnabled:          *wireStatus.ProtectionEnabled,
		ProtectionDisabledDuration: wireStatus.ProtectionDisabledDuration,
		DHCPAvailable:              wireStatus.DHCPAvailable,
		Running:                    *wireStatus.Running,
		Version:                    *wireStatus.Version,
		StartTime:                  wireStatus.StartTime,
	}, nil
}

// jsonError creates a structured status decoding error.
//
// The operation is recorded as "status" and the method as GET because this
// helper serves only the status endpoint.
//
// Parameters:
//   - cause: The JSON decoding or response-contract cause.
//
// Returns:
//   - An [Error] with [ErrorKindJSON] and the supplied cause.
func jsonError(cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = string(ErrorKindStatus)
	clientErr.Method = http.MethodGet
	clientErr.Err = cause

	return clientErr
}

// validateServerStatus enforces required fields and contract bounds.
//
// The required fields are checked in wire-contract order. Optional fields may
// remain nil. After presence validation, the DNS and HTTP ports must both be
// non-zero; their uint16 representation already excludes values above 65535.
//
// Parameters:
//   - status: The decoded wire status to validate.
//
// Returns:
//   - A missing-required-field or invalid-port error; otherwise nil.
func validateServerStatus(status serverStatusResponse) error {
	requiredFields := []struct {
		name  string
		value bool
	}{
		{name: "dns_addresses", value: status.DNSAddresses != nil},
		{name: "dns_port", value: status.DNSPort != nil},
		{name: "http_port", value: status.HTTPPort != nil},
		{name: "language", value: status.Language != nil},
		{name: "protection_enabled", value: status.ProtectionEnabled != nil},
		{name: "running", value: status.Running != nil},
		{name: "version", value: status.Version != nil},
	}
	for _, field := range requiredFields {
		if !field.value {
			return fmt.Errorf("%s: %w", field.name, errRequiredStatusField)
		}
	}

	if *status.DNSPort == 0 {
		return errInvalidDNSPort
	}
	if *status.HTTPPort == 0 {
		return errInvalidHTTPPort
	}

	return nil
}
