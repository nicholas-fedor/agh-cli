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

// InstallService exposes the first-install configuration operations.
type InstallService interface {
	InstallGetAddresses(ctx context.Context) (*AddressesInfo, error)
	InstallCheckConfig(ctx context.Context, request CheckConfigRequest) (*CheckConfigResponse, error)
	InstallConfigure(ctx context.Context, configuration InitialConfiguration) error
}

// AddressInfo contains an IP address and listening port used by the initial
// configuration request.
type AddressInfo struct {
	// IP is the address on which the service listens.
	IP string `json:"ip"`
	// Port is the listening port.
	Port uint16 `json:"port"`
}

// AddressesInfo contains the network interfaces and default ports reported by
// the installation endpoint.
type AddressesInfo struct {
	// DNSPort is the default DNS listening port.
	DNSPort uint16 `json:"dns_port"`
	// Interfaces contains the available network interfaces keyed by name.
	Interfaces map[string]NetInterface `json:"interfaces"`
	// Version is the AdGuard Home version.
	Version string `json:"version"`
	// WebPort is the default web-interface listening port.
	WebPort uint16 `json:"web_port"`
}

// NetInterface contains one network interface reported during installation.
type NetInterface struct {
	// Flags is the operating-system interface flags string.
	Flags string `json:"flags"`
	// GatewayIP is the interface gateway address.
	GatewayIP string `json:"gateway_ip"`
	// HardwareAddress is the interface hardware address.
	HardwareAddress string `json:"hardware_address"`
	// IPv4Addresses contains the interface's IPv4 addresses.
	IPv4Addresses []string `json:"ipv4_addresses"`
	// IPv6Addresses contains the interface's IPv6 addresses.
	IPv6Addresses []string `json:"ipv6_addresses"`
	// Name is the interface name.
	Name string `json:"name"`
}

// CheckConfigRequest contains the optional listener settings to validate.
type CheckConfigRequest struct {
	// DNS contains the optional DNS listener settings.
	DNS *CheckConfigRequestInfo `json:"dns,omitzero"`
	// Web contains the optional web listener settings.
	Web *CheckConfigRequestInfo `json:"web,omitzero"`
	// SetStaticIP optionally requests conversion to a static IP address.
	SetStaticIP *bool `json:"set_static_ip,omitzero"`
}

// CheckConfigRequestInfo contains optional settings for one listener.
type CheckConfigRequestInfo struct {
	// IP is the optional listener address.
	IP *string `json:"ip,omitzero"`
	// Port is the optional listener port.
	Port *uint16 `json:"port,omitzero"`
	// Autofix optionally requests an automatic fix for a conflicting port.
	Autofix *bool `json:"autofix,omitzero"`
}

// CheckConfigResponse contains the result of checking an installation
// configuration.
type CheckConfigResponse struct {
	// DNS contains the DNS listener check result.
	DNS CheckConfigResponseInfo `json:"dns"`
	// Web contains the web listener check result.
	Web CheckConfigResponseInfo `json:"web"`
	// StaticIP contains the optional static-IP check result.
	StaticIP CheckConfigStaticIPInfo `json:"static_ip"`
}

// CheckConfigResponseInfo contains the result for one listener.
type CheckConfigResponseInfo struct {
	// Status is the server's status text. An empty string is valid.
	Status string `json:"status"`
	// CanAutofix reports whether the server can automatically fix the issue.
	CanAutofix bool `json:"can_autofix"`
}

// CheckConfigStaticIPStatus identifies the static-IP check state.
type CheckConfigStaticIPStatus string

// CheckConfigStaticIPInfo contains optional static-IP check details.
type CheckConfigStaticIPInfo struct {
	// Static is the optional static-IP state.
	Static *CheckConfigStaticIPStatus `json:"static,omitzero"`
	// IP is the optional current dynamic address.
	IP *string `json:"ip,omitzero"`
	// Error is the optional error text reported by a failed check.
	Error *string `json:"error,omitzero"`
}

// InitialConfiguration contains the settings submitted to complete the initial
// installation.
type InitialConfiguration struct {
	// DNS contains the DNS listener settings.
	DNS AddressInfo `json:"dns"`
	// Web contains the web-interface listener settings.
	Web AddressInfo `json:"web"`
	// Username is the administrator username.
	Username string `json:"username"`
	// Password is the administrator password.
	Password string `json:"password"`
}

// installAddressesResponse mirrors the pinned get-addresses response schema.
//
// Pointer fields keep the difference between an absent or null value and a
// present value so that required-field validation can report a missing member.
type installAddressesResponse struct {
	// DNSPort is nil when the required DNS port is absent or null.
	DNSPort *uint16 `json:"dns_port"`
	// Interfaces is nil when the required interface map is absent or null.
	Interfaces *map[string]installInterfaceResponse `json:"interfaces"`
	// Version is nil when the required version is absent or null.
	Version *string `json:"version"`
	// WebPort is nil when the required web port is absent or null.
	WebPort *uint16 `json:"web_port"`
}

// installInterfaceResponse mirrors one entry of the pinned interface map.
//
// Every member is required, so each field is a pointer that is nil when the
// server omitted the member or returned JSON null.
type installInterfaceResponse struct {
	// Flags is nil when the required interface flags are absent or null.
	Flags *string `json:"flags"`
	// GatewayIP is nil when the required gateway address is absent or null.
	GatewayIP *string `json:"gateway_ip"`
	// HardwareAddress is nil when the required hardware address is absent or null.
	HardwareAddress *string `json:"hardware_address"`
	// IPv4Addresses is nil when the required IPv4 address list is absent or null.
	IPv4Addresses *[]string `json:"ipv4_addresses"`
	// IPv6Addresses is nil when the required IPv6 address list is absent or null.
	IPv6Addresses *[]string `json:"ipv6_addresses"`
	// Name is nil when the required interface name is absent or null.
	Name *string `json:"name"`
}

// checkConfigResponse mirrors the pinned check-configuration response schema.
//
// The members are required, so each field is a pointer that is nil when the
// server omitted the member or returned JSON null.
type checkConfigResponse struct {
	// DNS is nil when the required DNS listener result is absent or null.
	DNS *checkConfigResponseInfo `json:"dns"`
	// Web is nil when the required web listener result is absent or null.
	Web *checkConfigResponseInfo `json:"web"`
	// StaticIP is nil when the required static-IP result is absent or null.
	StaticIP *checkConfigStaticIPResponse `json:"static_ip"`
}

// checkConfigResponseInfo mirrors the pinned result for one listener.
type checkConfigResponseInfo struct {
	// Status is nil when the required status text is absent or null. An empty
	// string is a valid status.
	Status *string `json:"status"`
	// CanAutofix is nil when the required autofix flag is absent or null.
	CanAutofix *bool `json:"can_autofix"`
}

// checkConfigStaticIPResponse mirrors the pinned static-IP check result.
type checkConfigStaticIPResponse struct {
	// Static is nil when the optional static-IP state is absent or null.
	Static *CheckConfigStaticIPStatus `json:"static"`
	// IP is nil when the optional current address is absent or null.
	IP *string `json:"ip"`
	// Error is nil when the optional error text is absent or null.
	Error *string `json:"error"`
}

const (
	// CheckConfigStaticIPYes indicates that the address is static.
	CheckConfigStaticIPYes CheckConfigStaticIPStatus = statusValueYes
	// CheckConfigStaticIPNo indicates that the address is dynamic.
	CheckConfigStaticIPNo CheckConfigStaticIPStatus = statusValueNo
	// CheckConfigStaticIPError indicates that the static-IP check failed.
	CheckConfigStaticIPError CheckConfigStaticIPStatus = statusValueError
)

const (
	// OperationInstallGetAddresses identifies installation address retrieval.
	operationInstallGetAddresses = "install_get_addresses"
	// OperationInstallCheckConfig identifies installation configuration checks.
	operationInstallCheckConfig = "install_check_config"
	// OperationInstallConfigure identifies initial configuration submission.
	operationInstallConfigure = "install_configure"
)

var (
	_ InstallService = (*Client)(nil)

	// ErrNullInstallResponse identifies a null installation addresses response.
	errNullInstallResponse = errors.New("install addresses response must be a JSON object")
	// ErrRequiredInstallField identifies an absent required installation field.
	errRequiredInstallField = errors.New("required install response field is missing")
	// ErrRequiredCheckConfigField identifies an absent required check-configuration
	// field.
	errRequiredCheckConfigField = errors.New("required check configuration response field is missing")
	// ErrInvalidCheckConfigIPStatus identifies an unknown static-IP state.
	errInvalidCheckConfigIPStatus = errors.New("invalid check configuration static IP status")
)

// InstallGetAddresses retrieves the interfaces and default ports available to
// the first-install workflow.
//
// The request is GET /control/install/get_addresses. The response must be a
// JSON object containing all required address fields and all required members
// of every interface. Unknown members are ignored. The response is bounded by
// the configured client limit.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - addresses: The decoded installation addresses when the response is valid.
//   - err: An [Error] for request, redirect, HTTP, response-limit, response-body,
//     media-type, JSON, or required-field failures; otherwise nil.
func (c *Client) InstallGetAddresses(ctx context.Context) (*AddressesInfo, error) {
	response, requestErr := c.get(
		ctx,
		operationInstallGetAddresses,
		"control/install/get_addresses",
	)
	if requestErr != nil {
		return nil, requestErr
	}

	addresses, decodeErr := decodeInstallAddresses(response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return addresses, nil
}

// InstallCheckConfig validates the listener settings for an initial install.
//
// The request is POST /control/install/check_config and always contains a JSON
// object. Optional fields are omitted when nil, while nonnil false, zero, and
// empty values are preserved. The response must be a JSON object with the
// required DNS, web, and static-IP members.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: The optional listener settings to validate.
//
// Returns:
//   - result: The decoded configuration check result when the response is valid.
//   - err: An [Error] for request, redirect, HTTP, response-limit, response-body,
//     media-type, JSON, or required-field failures; otherwise nil.
func (c *Client) InstallCheckConfig(
	ctx context.Context,
	request CheckConfigRequest,
) (*CheckConfigResponse, error) {
	var wireResponse *checkConfigResponse

	requestErr := c.postJSON(
		ctx,
		operationInstallCheckConfig,
		http.MethodPost,
		"control/install/check_config",
		request,
		&wireResponse,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	result, decodeErr := checkConfigFromWire(wireResponse)
	if decodeErr != nil {
		return nil, installJSONError(operationInstallCheckConfig, http.MethodPost, decodeErr)
	}

	return result, nil
}

// InstallConfigure applies the initial AdGuard Home configuration.
//
// The request is POST /control/install/configure and always contains the
// required JSON configuration object. The response is treated as an empty
// response mode: its body is bounded and closed but is not decoded, and its
// media type is not required.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - configuration: The initial server configuration.
//
// Returns:
//   - err: An [Error] for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) InstallConfigure(ctx context.Context, configuration InitialConfiguration) error {
	requestErr := c.postEmpty(
		ctx,
		operationInstallConfigure,
		http.MethodPost,
		"control/install/configure",
		configuration,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// decodeInstallAddresses strictly decodes and validates an install-address
// response.
//
// Parameters:
//   - body: The bounded JSON response body.
//
// Returns:
//   - addresses: The decoded addresses when the response is valid.
//   - err: A JSON-kind *Error for malformed, null, or invalid responses;
//     otherwise nil.
func decodeInstallAddresses(body []byte) (*AddressesInfo, *Error) {
	var wireResponse *installAddressesResponse

	err := json.Unmarshal(body, &wireResponse)
	if err != nil {
		return nil, installJSONError(
			operationInstallGetAddresses,
			http.MethodGet,
			fmt.Errorf("decode response: %w", err),
		)
	}
	if wireResponse == nil {
		return nil, installJSONError(
			operationInstallGetAddresses,
			http.MethodGet,
			errNullInstallResponse,
		)
	}

	if wireResponse.DNSPort == nil ||
		wireResponse.Interfaces == nil ||
		wireResponse.Version == nil ||
		wireResponse.WebPort == nil {

		return nil, installJSONError(
			operationInstallGetAddresses,
			http.MethodGet,
			errRequiredInstallField,
		)
	}

	interfaces := make(map[string]NetInterface, len(*wireResponse.Interfaces))
	for name, wireInterface := range *wireResponse.Interfaces {
		err = validateInstallInterface(wireInterface)
		if err != nil {
			return nil, installJSONError(
				operationInstallGetAddresses,
				http.MethodGet,
				fmt.Errorf("interfaces[%q]: %w", name, err),
			)
		}

		interfaces[name] = NetInterface{
			Flags:           *wireInterface.Flags,
			GatewayIP:       *wireInterface.GatewayIP,
			HardwareAddress: *wireInterface.HardwareAddress,
			IPv4Addresses:   *wireInterface.IPv4Addresses,
			IPv6Addresses:   *wireInterface.IPv6Addresses,
			Name:            *wireInterface.Name,
		}
	}

	return &AddressesInfo{
		DNSPort:    *wireResponse.DNSPort,
		Interfaces: interfaces,
		Version:    *wireResponse.Version,
		WebPort:    *wireResponse.WebPort,
	}, nil
}

// validateInstallInterface checks every required member of one interface.
//
// Parameters:
//   - networkInterface: The decoded interface to validate.
//
// Returns:
//   - err: A missing-required-field error; otherwise nil.
func validateInstallInterface(networkInterface installInterfaceResponse) error {
	if networkInterface.Flags == nil ||
		networkInterface.GatewayIP == nil ||
		networkInterface.HardwareAddress == nil ||
		networkInterface.IPv4Addresses == nil ||
		networkInterface.IPv6Addresses == nil ||
		networkInterface.Name == nil {

		return errRequiredInstallField
	}

	return nil
}

// checkConfigFromWire converts a decoded check-configuration response.
//
// Parameters:
//   - response: The decoded wire response. It must not be nil.
//
// Returns:
//   - result: The public response when all required members are present.
//   - err: A response-contract error; otherwise nil.
func checkConfigFromWire(response *checkConfigResponse) (*CheckConfigResponse, error) {
	err := validateCheckConfigResponse(response)
	if err != nil {
		return nil, fmt.Errorf("validate check configuration response: %w", err)
	}

	return &CheckConfigResponse{
		DNS: CheckConfigResponseInfo{
			Status:     *response.DNS.Status,
			CanAutofix: *response.DNS.CanAutofix,
		},
		Web: CheckConfigResponseInfo{
			Status:     *response.Web.Status,
			CanAutofix: *response.Web.CanAutofix,
		},
		StaticIP: CheckConfigStaticIPInfo{
			Static: response.StaticIP.Static,
			IP:     response.StaticIP.IP,
			Error:  response.StaticIP.Error,
		},
	}, nil
}

// validateCheckConfigResponse validates required check-configuration members.
//
// Parameters:
//   - response: The decoded response to validate.
//
// Returns:
//   - err: A missing-required-field or invalid-enum error; otherwise nil.
func validateCheckConfigResponse(response *checkConfigResponse) error {
	if response == nil || response.DNS == nil || response.Web == nil || response.StaticIP == nil {
		return errRequiredCheckConfigField
	}
	if response.DNS.Status == nil || response.DNS.CanAutofix == nil ||
		response.Web.Status == nil || response.Web.CanAutofix == nil {

		return errRequiredCheckConfigField
	}

	err := validateCheckConfigStaticIP(response.StaticIP)
	if err != nil {
		return fmt.Errorf("validate static IP response: %w", err)
	}

	return nil
}

// validateCheckConfigStaticIP validates an optional static-IP state value.
//
// Parameters:
//   - response: The static-IP response to validate.
//
// Returns:
//   - err: An invalid-state error; otherwise nil.
func validateCheckConfigStaticIP(response *checkConfigStaticIPResponse) error {
	if response.Static == nil {
		return nil
	}

	switch *response.Static {
	case CheckConfigStaticIPYes, CheckConfigStaticIPNo, CheckConfigStaticIPError:
		return nil
	default:
		return errInvalidCheckConfigIPStatus
	}
}

// installJSONError creates a structured install JSON error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The decoding or response-contract cause.
//
// Returns:
//   - The structured JSON error.
func installJSONError(operation, method string, cause error) *Error {
	return globalJSONError(operation, method, cause)
}
