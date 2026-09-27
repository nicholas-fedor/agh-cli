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

// TLSService exposes TLS status, configuration, and validation.
type TLSService interface {
	TLSStatus(ctx context.Context) (*TLSConfig, error)
	TLSConfigure(ctx context.Context, config TLSConfig) (*TLSConfig, error)
	TLSValidate(ctx context.Context, config TLSConfig) (*TLSConfig, error)
}

// TLSKeyType is a response-only private-key algorithm reported by AdGuard Home.
//
// The client accepts only TLSKeyTypeRSA and TLSKeyTypeECDSA when decoding a
// response.
type TLSKeyType string

// TLSConfig represents optional AdGuard Home TLS settings and status values.
//
// TLSConfigure and TLSValidate always send a JSON object. A nil field is
// omitted, while a nonnil field preserves explicit false, zero, empty-string,
// or empty-slice values. A zero TLSConfig therefore produces an empty JSON
// object rather than an omitted body.
//
// Response fields are optional unless documented otherwise. Nil represents an
// absent or null response field. Fields documented as response-only should be
// left nil in request values; the current wire model serializes any nonnil
// field, including a response-only field.
type TLSConfig struct {
	// Enabled is the optional TLS service state. Nil omits the field in a
	// request and represents an absent or null value in a response.
	Enabled *bool `json:"enabled,omitzero"`
	// ServerName is the optional TLS server name. Nil omits the field in a
	// request and represents an absent or null value in a response.
	ServerName *string `json:"server_name,omitzero"`
	// ForceHTTPS is the optional HTTPS redirection state. Nil omits the field
	// in a request and represents an absent or null value in a response.
	ForceHTTPS *bool `json:"force_https,omitzero"`
	// PortHTTPS is the optional HTTPS listening port. Nil omits the field in a
	// request and preserves an explicit zero value when nonnil.
	PortHTTPS *uint16 `json:"port_https,omitzero"`
	// PortDNSOverTLS is the optional DNS-over-TLS listening port. Nil omits the
	// field in a request and preserves an explicit zero value when nonnil.
	PortDNSOverTLS *uint16 `json:"port_dns_over_tls,omitzero"`
	// PortDNSOverQUIC is the optional DNS-over-QUIC listening port. Nil omits
	// the field in a request and preserves an explicit zero value when nonnil.
	PortDNSOverQUIC *uint16 `json:"port_dns_over_quic,omitzero"`
	// CertificateChain is the optional PEM-encoded certificate chain. Nil
	// omits the field in a request and represents an absent or null response.
	CertificateChain *string `json:"certificate_chain,omitzero"`
	// PrivateKey is the optional request-only PEM-encoded private key. The
	// client does not expect the server to return private-key contents.
	PrivateKey *string `json:"private_key,omitzero"`
	// PrivateKeySaved is the optional state indicating whether AdGuard Home has
	// saved private-key material.
	PrivateKeySaved *bool `json:"private_key_saved,omitzero"`
	// CertificatePath is the optional certificate file path.
	CertificatePath *string `json:"certificate_path,omitzero"`
	// PrivateKeyPath is the optional private-key file path.
	PrivateKeyPath *string `json:"private_key_path,omitzero"`
	// ValidCertificate is a response-only certificate validation result.
	ValidCertificate *bool `json:"valid_cert,omitzero"`
	// ValidChain is a response-only certificate-chain validation result.
	ValidChain *bool `json:"valid_chain,omitzero"`
	// Subject is the response-only certificate subject.
	Subject *string `json:"subject,omitzero"`
	// Issuer is the response-only certificate issuer.
	Issuer *string `json:"issuer,omitzero"`
	// NotBefore is the response-only certificate validity start timestamp.
	NotBefore *string `json:"not_before,omitzero"`
	// NotAfter is the response-only certificate expiration timestamp.
	NotAfter *string `json:"not_after,omitzero"`
	// DNSNames is the response-only list of certificate DNS names. Nil means
	// that the field was absent or null; a pointer to an empty slice means
	// that the server returned an empty list.
	DNSNames *[]string `json:"dns_names,omitzero"`
	// ValidKey is a response-only private-key validation result.
	ValidKey *bool `json:"valid_key,omitzero"`
	// KeyType is the response-only private-key algorithm. When present, it
	// must be TLSKeyTypeRSA or TLSKeyTypeECDSA.
	KeyType *TLSKeyType `json:"key_type,omitzero"`
	// WarningValidation is the response-only certificate validation warning.
	WarningValidation *string `json:"warning_validation,omitzero"`
	// ValidPair is a response-only certificate and private-key pair validation
	// result.
	ValidPair *bool `json:"valid_pair,omitzero"`
	// ServePlainDNS is the optional plain-DNS serving state.
	ServePlainDNS *bool `json:"serve_plain_dns,omitzero"`
}

const (
	// TLSKeyTypeRSA identifies an RSA private key.
	TLSKeyTypeRSA TLSKeyType = "RSA"
	// TLSKeyTypeECDSA identifies an elliptic-curve private key.
	TLSKeyTypeECDSA TLSKeyType = "ECDSA"
)

const (
	// TLSStatusOperation identifies TLSStatus errors.
	tlsStatusOperation = "tls_status"
	// TLSConfigureOperation identifies TLSConfigure errors.
	tlsConfigureOperation = "tls_configure"
	// TLSValidateOperation identifies TLSValidate errors.
	tlsValidateOperation = "tls_validate"
)

var (
	_ TLSService = (*Client)(nil)
	// ErrRequiredTLSResponse identifies a response that is not a JSON object.
	errRequiredTLSResponse = errors.New("TLS response must be a JSON object")
	// ErrInvalidTLSKeyType identifies an unsupported TLS private-key type.
	errInvalidTLSKeyType = errors.New("invalid TLS key type")
)

// TLSStatus retrieves the current AdGuard Home TLS configuration.
//
// The response must be a JSON object. All fields are optional, and a present
// key type must be RSA or ECDSA.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - config: The decoded TLS configuration when the response is valid.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON,
//     required-object, or invalid-key-type failures; otherwise nil.
func (c *Client) TLSStatus(ctx context.Context) (*TLSConfig, error) {
	response, requestErr := c.get(ctx, tlsStatusOperation, "control/tls/status")
	if requestErr != nil {
		return nil, requestErr
	}

	var config *TLSConfig

	err := json.Unmarshal(response.body, &config)
	if err != nil {
		return nil, tlsJSONError(tlsStatusOperation, http.MethodGet, fmt.Errorf("decode response: %w", err))
	}

	err = validateTLSConfig(config)
	if err != nil {
		return nil, tlsJSONError(tlsStatusOperation, http.MethodGet, err)
	}

	return config, nil
}

// TLSConfigure applies a TLS configuration.
//
// The config value is always sent as a JSON object. Nil fields are omitted,
// while nonnil fields preserve explicit false, zero, empty-string, and
// empty-slice values. The response must be a JSON object, and a present key
// type must be RSA or ECDSA.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The TLS settings to apply.
//
// Returns:
//   - config: The TLS configuration reported by AdGuard Home after the update.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON,
//     required-object, or invalid-key-type failures; otherwise nil.
func (c *Client) TLSConfigure(ctx context.Context, config TLSConfig) (*TLSConfig, error) {
	result, requestErr := c.executeTLSJSONOperation(
		ctx,
		tlsConfigureOperation,
		"control/tls/configure",
		&config,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	return result, nil
}

// TLSValidate validates a TLS configuration without applying it.
//
// The config value is always sent as a JSON object. Nil fields are omitted,
// while nonnil fields preserve explicit false, zero, empty-string, and
// empty-slice values. The response must be a JSON object, and a present key
// type must be RSA or ECDSA.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The TLS settings to validate.
//
// Returns:
//   - config: The validation results reported by AdGuard Home.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON,
//     required-object, or invalid-key-type failures; otherwise nil.
func (c *Client) TLSValidate(ctx context.Context, config TLSConfig) (*TLSConfig, error) {
	result, requestErr := c.executeTLSJSONOperation(
		ctx,
		tlsValidateOperation,
		"control/tls/validate",
		&config,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	return result, nil
}

// executeTLSJSONOperation posts a TLS configuration and validates the returned
// object.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - config: The TLS configuration to send.
//
// Returns:
//   - config: The validated TLS response when the operation succeeds.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON,
//     required-object, or invalid-key-type failures; otherwise nil.
func (c *Client) executeTLSJSONOperation(
	ctx context.Context,
	operation string,
	endpoint string,
	config *TLSConfig,
) (*TLSConfig, *Error) {
	var result *TLSConfig

	requestErr := c.postJSON(
		ctx,
		operation,
		http.MethodPost,
		endpoint,
		config,
		&result,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	err := validateTLSConfig(result)
	if err != nil {
		return nil, tlsJSONError(operation, http.MethodPost, err)
	}

	return result, nil
}

// validateTLSConfig validates the required response shape and optional key
// type of a TLS configuration.
//
// Parameters:
//   - config: The decoded TLS response. It must not be nil.
//
// Returns:
//   - err: An error identifying a missing response object or invalid key type;
//     otherwise nil.
func validateTLSConfig(config *TLSConfig) error {
	if config == nil {
		return errRequiredTLSResponse
	}
	if config.KeyType == nil {
		return nil
	}

	switch *config.KeyType {
	case TLSKeyTypeRSA, TLSKeyTypeECDSA:
		return nil
	default:
		return errInvalidTLSKeyType
	}
}

// tlsJSONError creates a structured TLS JSON decoding or validation error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The decoding or validation cause.
//
// Returns:
//   - err: The structured JSON error.
func tlsJSONError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}
