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

// DHCPService exposes DHCP status, configuration, discovery, and lease management.
type DHCPService interface {
	DHCPStatus(ctx context.Context) (*DHCPStatus, error)
	DHCPInterfaces(ctx context.Context) (map[string]DHCPInterface, error)
	DHCPConfig(ctx context.Context, config *DHCPConfig) error
	DHCPFindActive(ctx context.Context, request *DHCPFindRequest) (*DHCPFindResult, error)
	DHCPAddStaticLease(ctx context.Context, lease DHCPStaticLease) error
	DHCPRemoveStaticLease(ctx context.Context, lease DHCPStaticLease) error
	DHCPUpdateStaticLease(ctx context.Context, lease DHCPStaticLease) error
	DHCPReset(ctx context.Context) error
	DHCPResetLeases(ctx context.Context) error
}

// DHCPConfig represents optional AdGuard Home DHCP server settings.
//
// In a request, a nil *DHCPConfig omits the JSON body, while a nonnil value
// sends an object. Every field is optional: nil omits that field, and nonnil
// preserves explicit false, zero, or empty values. The same type exposes
// nullable values in DHCPStatus responses.
type DHCPConfig struct {
	// Enabled is the optional DHCP service state. Nil omits the field in a
	// request and represents an absent or null value in a response.
	Enabled *bool `json:"enabled,omitzero"`
	// InterfaceName is the optional network interface name. Nil omits the
	// field in a request and represents an absent or null value in a response.
	InterfaceName *string `json:"interface_name,omitzero"`
	// V4 contains optional IPv4 DHCP settings. Nil omits the entire object.
	V4 *DHCPConfigV4 `json:"v4,omitzero"`
	// V6 contains optional IPv6 DHCP settings. Nil omits the entire object.
	V6 *DHCPConfigV6 `json:"v6,omitzero"`
}

// DHCPConfigV4 contains optional IPv4 DHCP settings and response values.
//
// Every field is optional. Nil omits the field in a request and represents an
// absent or null value in a response.
type DHCPConfigV4 struct {
	// GatewayIP is the optional IPv4 gateway address.
	GatewayIP *string `json:"gateway_ip,omitzero"`
	// SubnetMask is the optional IPv4 subnet mask.
	SubnetMask *string `json:"subnet_mask,omitzero"`
	// RangeStart is the optional first address in the IPv4 assignment range.
	RangeStart *string `json:"range_start,omitzero"`
	// RangeEnd is the optional last address in the IPv4 assignment range.
	RangeEnd *string `json:"range_end,omitzero"`
	// LeaseDuration is the optional lease duration in seconds.
	LeaseDuration *int64 `json:"lease_duration,omitzero"`
}

// DHCPConfigV6 contains optional IPv6 DHCP settings and response values.
//
// Every field is optional. Nil omits the field in a request and represents an
// absent or null value in a response.
type DHCPConfigV6 struct {
	// RangeStart is the optional first address in the IPv6 assignment range.
	RangeStart *string `json:"range_start,omitzero"`
	// LeaseDuration is the optional lease duration in seconds.
	LeaseDuration *int64 `json:"lease_duration,omitzero"`
}

// DHCPLease is a response-only dynamic DHCP lease.
//
// All fields are required. DHCPStatus rejects a lease whose fields are absent
// or null.
type DHCPLease struct {
	// Expires is the lease expiration timestamp reported by the server.
	Expires string
	// Hostname is the lease hostname reported by the server.
	Hostname string
	// IP is the address assigned by the DHCP server.
	IP string
	// MAC is the hardware address associated with the lease.
	MAC string
}

// DHCPStaticLease is a required static DHCP lease used in requests and responses.
//
// All fields are required. The client always serializes all three fields for
// add, remove, and update requests, and rejects response leases with an absent
// or null field.
type DHCPStaticLease struct {
	// Hostname is the static lease hostname.
	Hostname string `json:"hostname"`
	// IP is the address reserved for the static lease.
	IP string `json:"ip"`
	// MAC is the hardware address reserved for the static lease.
	MAC string `json:"mac"`
}

// DHCPStatus is a response-only snapshot of the AdGuard Home DHCP service.
//
// Leases is required and may be empty. Other fields are optional: nil means
// that the server omitted the field or returned JSON null. StaticLeases
// distinguishes an absent or null list, represented by nil, from an empty list,
// represented by a nonnil pointer to an empty slice.
type DHCPStatus struct {
	// Enabled is the optional DHCP service state.
	Enabled *bool
	// InterfaceName is the optional interface selected by the DHCP service.
	InterfaceName *string
	// V4 contains optional IPv4 DHCP settings.
	V4 *DHCPConfigV4
	// V6 contains optional IPv6 DHCP settings.
	V6 *DHCPConfigV6
	// Leases contains the required dynamic lease list. An empty slice means
	// that the server returned an empty list.
	Leases []DHCPLease
	// StaticLeases is the optional static lease list. Nil means that the field
	// was absent or null; a pointer to an empty slice means that it was empty.
	StaticLeases *[]DHCPStaticLease
}

// DHCPInterface is a response-only network interface available to the DHCP
// service.
//
// All fields are required. DHCPInterfaces rejects an interface with an absent
// or null field.
type DHCPInterface struct {
	// Flags is the operating-system interface flags string.
	Flags string
	// GatewayIP is the interface's IPv4 gateway address.
	GatewayIP string
	// HardwareAddress is the interface's hardware address.
	HardwareAddress string
	// IPv4Addresses contains the interface's IPv4 addresses with prefix
	// lengths. An empty slice means that no addresses were reported.
	IPv4Addresses []string
	// IPv6Addresses contains the interface's IPv6 addresses with prefix
	// lengths. An empty slice means that no addresses were reported.
	IPv6Addresses []string
	// Name is the interface name.
	Name string
}

// DHCPFindRequest contains optional criteria for an active DHCP server search.
//
// A nil *DHCPFindRequest causes DHCPFindActive to omit the request body, while
// a nonnil value sends an object. A nil Interface field is omitted.
type DHCPFindRequest struct {
	// Interface optionally restricts the search to the named interface.
	Interface *string `json:"interface,omitzero"`
}

// DHCPSearchStatus is a response-only status returned by an active DHCP search.
//
// The client accepts only the values defined by DHCPSearchStatusYes,
// DHCPSearchStatusNo, and DHCPSearchStatusError.
type DHCPSearchStatus string

// DHCPFindResult is the response-only result of an active DHCP server search.
//
// V4 and V6 are optional. Nil means that the server omitted the family result
// or returned JSON null.
type DHCPFindResult struct {
	// V4 contains the optional IPv4 search result.
	V4 *DHCPFindResultV4 `json:"v4,omitzero"`
	// V6 contains the optional IPv6 search result.
	V6 *DHCPFindResultV6 `json:"v6,omitzero"`
}

// DHCPFindResultV4 contains optional IPv4 active-search results.
//
// OtherServer and StaticIP are optional. Nil means that the server omitted the
// result or returned JSON null.
type DHCPFindResultV4 struct {
	// OtherServer contains the optional other-server search result.
	OtherServer *DHCPOtherServerResult `json:"other_server,omitzero"`
	// StaticIP contains the optional static-IP search result.
	StaticIP *DHCPStaticIPResult `json:"static_ip,omitzero"`
}

// DHCPFindResultV6 contains an optional IPv6 active-search result.
//
// OtherServer is optional. Nil means that the server omitted the result or
// returned JSON null.
type DHCPFindResultV6 struct {
	// OtherServer contains the optional other-server search result.
	OtherServer *DHCPOtherServerResult `json:"other_server,omitzero"`
}

// DHCPOtherServerResult contains optional results from another DHCP server.
//
// Found and Error are optional. Nil means that the server omitted the field or
// returned JSON null. When Found is present, it must be a documented search
// status value.
type DHCPOtherServerResult struct {
	// Found is the optional outcome reported for another DHCP server.
	Found *DHCPSearchStatus `json:"found,omitzero"`
	// Error is the optional diagnostic message reported for a failed search.
	Error *string `json:"error,omitzero"`
}

// DHCPStaticIPResult contains an optional static-IP search result.
//
// Status and IP are optional. Nil means that the server omitted the field or
// returned JSON null. When Status is present, it must be a documented search
// status value.
type DHCPStaticIPResult struct {
	// Status is the optional outcome of the static-IP search.
	Status *DHCPSearchStatus `json:"static,omitzero"`
	// IP is the optional address reported by the static-IP search.
	IP *string `json:"ip,omitzero"`
}

// dhcpConfigV4Response preserves the presence of IPv4 DHCP response values.
type dhcpConfigV4Response struct {
	// GatewayIP is nil when the response omits the field or returns null.
	GatewayIP *string `json:"gateway_ip"`
	// SubnetMask is nil when the response omits the field or returns null.
	SubnetMask *string `json:"subnet_mask"`
	// RangeStart is nil when the response omits the field or returns null.
	RangeStart *string `json:"range_start"`
	// RangeEnd is nil when the response omits the field or returns null.
	RangeEnd *string `json:"range_end"`
	// LeaseDuration is nil when the response omits the field or returns null.
	LeaseDuration *int64 `json:"lease_duration"`
}

// dhcpConfigV6Response preserves the presence of IPv6 DHCP response values.
type dhcpConfigV6Response struct {
	// RangeStart is nil when the response omits the field or returns null.
	RangeStart *string `json:"range_start"`
	// LeaseDuration is nil when the response omits the field or returns null.
	LeaseDuration *int64 `json:"lease_duration"`
}

// dhcpLeaseResponse preserves required dynamic lease response fields.
type dhcpLeaseResponse struct {
	// Expires is nil when the required field is absent or null.
	Expires *string `json:"expires"`
	// Hostname is nil when the required field is absent or null.
	Hostname *string `json:"hostname"`
	// IP is nil when the required field is absent or null.
	IP *string `json:"ip"`
	// MAC is nil when the required field is absent or null.
	MAC *string `json:"mac"`
}

// dhcpStaticLeaseResponse preserves required static lease response fields.
type dhcpStaticLeaseResponse struct {
	// Hostname is nil when the required field is absent or null.
	Hostname *string `json:"hostname"`
	// IP is nil when the required field is absent or null.
	IP *string `json:"ip"`
	// MAC is nil when the required field is absent or null.
	MAC *string `json:"mac"`
}

// dhcpStatusResponse preserves optional and required DHCP status fields.
type dhcpStatusResponse struct {
	// Enabled is nil when the optional field is absent or null.
	Enabled *bool `json:"enabled"`
	// InterfaceName is nil when the optional field is absent or null.
	InterfaceName *string `json:"interface_name"`
	// V4 is nil when the optional object is absent or null.
	V4 *dhcpConfigV4Response `json:"v4"`
	// V6 is nil when the optional object is absent or null.
	V6 *dhcpConfigV6Response `json:"v6"`
	// Leases is nil when the required list is absent or null.
	Leases *[]dhcpLeaseResponse `json:"leases"`
	// StaticLeases is nil when the optional list is absent or null.
	StaticLeases *[]dhcpStaticLeaseResponse `json:"static_leases"`
}

// dhcpInterfaceResponse preserves required DHCP interface response fields.
type dhcpInterfaceResponse struct {
	// Flags is nil when the required field is absent or null.
	Flags *string `json:"flags"`
	// GatewayIP is nil when the required field is absent or null.
	GatewayIP *string `json:"gateway_ip"`
	// HardwareAddress is nil when the required field is absent or null.
	HardwareAddress *string `json:"hardware_address"`
	// IPv4Addresses is nil when the required list is absent or null.
	IPv4Addresses *[]string `json:"ipv4_addresses"`
	// IPv6Addresses is nil when the required list is absent or null.
	IPv6Addresses *[]string `json:"ipv6_addresses"`
	// Name is nil when the required field is absent or null.
	Name *string `json:"name"`
}

const (
	// DHCPSearchStatusYes means that the active search found a matching server.
	DHCPSearchStatusYes DHCPSearchStatus = statusValueYes
	// DHCPSearchStatusNo means that the active search found no matching server.
	DHCPSearchStatusNo DHCPSearchStatus = statusValueNo
	// DHCPSearchStatusError means that the active search encountered an error.
	DHCPSearchStatusError DHCPSearchStatus = statusValueError
)

const (
	// DhcpStatusOperation identifies DHCPStatus errors.
	dhcpStatusOperation = "dhcp_status"
	// DhcpInterfacesOperation identifies DHCPInterfaces errors.
	dhcpInterfacesOperation = "dhcp_interfaces"
	// DhcpConfigOperation identifies DHCPConfig errors.
	dhcpConfigOperation = "dhcp_config"
	// DhcpFindActiveOperation identifies DHCPFindActive errors.
	dhcpFindActiveOperation = "dhcp_find_active"
	// DhcpAddStaticLeaseOperation identifies DHCPAddStaticLease errors.
	dhcpAddStaticLeaseOperation = "dhcp_add_static_lease"
	// DhcpRemoveStaticLeaseOperation identifies DHCPRemoveStaticLease errors.
	dhcpRemoveStaticLeaseOperation = "dhcp_remove_static_lease"
	// DhcpUpdateStaticLeaseOperation identifies DHCPUpdateStaticLease errors.
	dhcpUpdateStaticLeaseOperation = "dhcp_update_static_lease"
	// DhcpResetOperation identifies DHCPReset errors.
	dhcpResetOperation = "dhcp_reset"
	// DhcpResetLeasesOperation identifies DHCPResetLeases errors.
	dhcpResetLeasesOperation = "dhcp_reset_leases"
)

var (
	_ DHCPService = (*Client)(nil)
	// ErrRequiredDHCPStatusField identifies a missing required DHCP status field.
	errRequiredDHCPStatusField = errors.New("required DHCP status field is missing")
	// ErrRequiredDHCPLeaseField identifies a missing required dynamic lease field.
	errRequiredDHCPLeaseField = errors.New("required DHCP lease field is missing")
	// ErrRequiredDHCPStaticLease identifies a missing required static lease field.
	errRequiredDHCPStaticLease = errors.New("required DHCP static lease field is missing")
	// ErrRequiredDHCPInterface identifies a missing required interface field.
	errRequiredDHCPInterface = errors.New("required DHCP interface field is missing")
	// ErrInvalidDHCPSearchStatus identifies an unsupported active-search status.
	errInvalidDHCPSearchStatus = errors.New("invalid DHCP search status")
)

// DHCPStatus retrieves the current DHCP service status.
//
// The response must contain a leases array, and every dynamic lease must
// contain all required fields. Optional status fields preserve the difference
// between a reported value and an absent or null value.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - status: The decoded DHCP status when the response is valid.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON, or
//     required-field failures; otherwise nil.
func (c *Client) DHCPStatus(ctx context.Context) (*DHCPStatus, error) {
	response, requestErr := c.get(ctx, dhcpStatusOperation, "control/dhcp/status")
	if requestErr != nil {
		return nil, requestErr
	}

	var wireStatus *dhcpStatusResponse

	err := json.Unmarshal(response.body, &wireStatus)
	if err != nil {
		return nil, dhcpJSONError(dhcpStatusOperation, http.MethodGet, fmt.Errorf("decode response: %w", err))
	}

	status, err := dhcpStatusFromWire(wireStatus)
	if err != nil {
		return nil, dhcpJSONError(dhcpStatusOperation, http.MethodGet, err)
	}

	return status, nil
}

// DHCPInterfaces retrieves the network interfaces available to the DHCP service.
//
// The response must be a JSON object. Each interface value must contain all
// required fields, although its address slices may be empty.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - interfaces: The decoded interfaces keyed by interface name.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON, or
//     required-field failures; otherwise nil.
func (c *Client) DHCPInterfaces(ctx context.Context) (map[string]DHCPInterface, error) {
	response, requestErr := c.get(ctx, dhcpInterfacesOperation, "control/dhcp/interfaces")
	if requestErr != nil {
		return nil, requestErr
	}

	var wireInterfaces *map[string]*dhcpInterfaceResponse

	err := json.Unmarshal(response.body, &wireInterfaces)
	if err != nil {
		return nil, dhcpJSONError(dhcpInterfacesOperation, http.MethodGet, fmt.Errorf("decode response: %w", err))
	}
	if wireInterfaces == nil {
		return nil, dhcpJSONError(
			dhcpInterfacesOperation,
			http.MethodGet,
			errRequiredDHCPInterface,
		)
	}

	interfaces, err := dhcpInterfacesFromWire(*wireInterfaces)
	if err != nil {
		return nil, dhcpJSONError(dhcpInterfacesOperation, http.MethodGet, err)
	}

	return interfaces, nil
}

// DHCPConfig updates the DHCP service configuration.
//
// A nil config omits the request body. A nonnil config sends a JSON object;
// nil fields are omitted, while nonnil fields preserve explicit false, zero,
// empty, and nested-object values.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - config: The optional configuration to send. Pass nil to omit the body.
//
// Returns:
//   - err: An *Error for request, HTTP, or response-limit failures; otherwise
//     nil.
func (c *Client) DHCPConfig(ctx context.Context, config *DHCPConfig) error {
	if config == nil {
		requestErr := c.postNoContent(ctx, dhcpConfigOperation, "control/dhcp/set_config")
		if requestErr != nil {
			return requestErr
		}

		return nil
	}

	requestErr := c.postEmpty(
		ctx,
		dhcpConfigOperation,
		http.MethodPost,
		"control/dhcp/set_config",
		config,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// DHCPFindActive searches for active DHCP servers.
//
// A nil request omits the JSON body, while a nonnil request sends an object.
// A nil interface criterion is omitted. The response must be a JSON object,
// and every search status that is present must be a documented constant.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - request: Optional search criteria. Pass nil to omit the body.
//
// Returns:
//   - result: The decoded active-server search result when the response is
//     valid.
//   - err: An *Error for request, HTTP, response-limit, media-type, JSON,
//     required-object, or invalid-status failures; otherwise nil.
func (c *Client) DHCPFindActive(
	ctx context.Context,
	request *DHCPFindRequest,
) (*DHCPFindResult, error) {
	var result *DHCPFindResult

	if request == nil {
		requestErr := c.postDHCPNoBodyJSON(
			ctx,
			dhcpFindActiveOperation,
			"control/dhcp/find_active_dhcp",
			&result,
		)
		if requestErr != nil {
			return nil, requestErr
		}
	} else {
		requestErr := c.postJSON(
			ctx,
			dhcpFindActiveOperation,
			http.MethodPost,
			"control/dhcp/find_active_dhcp",
			request,
			&result,
		)
		if requestErr != nil {
			return nil, requestErr
		}
	}

	if result == nil {
		return nil, dhcpJSONError(dhcpFindActiveOperation, http.MethodPost, errRequiredDHCPStatusField)
	}

	err := validateDHCPFindResult(result)
	if err != nil {
		return nil, dhcpJSONError(dhcpFindActiveOperation, http.MethodPost, err)
	}

	return result, nil
}

// DHCPAddStaticLease adds a static DHCP lease.
//
// The hostname, IP address, and hardware address are required by the API
// contract and are always serialized in the request.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - lease: The static lease to add.
//
// Returns:
//   - err: An *Error for request, HTTP, or response-limit failures; otherwise
//     nil.
func (c *Client) DHCPAddStaticLease(ctx context.Context, lease DHCPStaticLease) error {
	requestErr := c.postEmpty(
		ctx,
		dhcpAddStaticLeaseOperation,
		http.MethodPost,
		"control/dhcp/add_static_lease",
		lease,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// DHCPRemoveStaticLease removes a static DHCP lease.
//
// The hostname, IP address, and hardware address are required by the API
// contract and are always serialized in the request.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - lease: The static lease to remove.
//
// Returns:
//   - err: An *Error for request, HTTP, or response-limit failures; otherwise
//     nil.
func (c *Client) DHCPRemoveStaticLease(ctx context.Context, lease DHCPStaticLease) error {
	requestErr := c.postEmpty(
		ctx,
		dhcpRemoveStaticLeaseOperation,
		http.MethodPost,
		"control/dhcp/remove_static_lease",
		lease,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// DHCPUpdateStaticLease updates a static DHCP lease.
//
// The hostname, IP address, and hardware address are required by the API
// contract and are always serialized in the request.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - lease: The replacement static lease.
//
// Returns:
//   - err: An *Error for request, HTTP, or response-limit failures; otherwise
//     nil.
func (c *Client) DHCPUpdateStaticLease(ctx context.Context, lease DHCPStaticLease) error {
	requestErr := c.postEmpty(
		ctx,
		dhcpUpdateStaticLeaseOperation,
		http.MethodPost,
		"control/dhcp/update_static_lease",
		lease,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// DHCPReset resets the DHCP service configuration.
//
// The request has no body and accepts an empty successful response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, HTTP, or response-limit failures; otherwise
//     nil.
func (c *Client) DHCPReset(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, dhcpResetOperation, "control/dhcp/reset")
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// DHCPResetLeases removes all dynamic DHCP leases.
//
// The request has no body and accepts an empty successful response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An *Error for request, HTTP, or response-limit failures; otherwise
//     nil.
func (c *Client) DHCPResetLeases(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, dhcpResetLeasesOperation, "control/dhcp/reset_leases")
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// postDHCPNoBodyJSON executes a POST without a body and decodes its JSON
// response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation name placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - result: The destination for the decoded JSON response.
//
// Returns:
//   - err: An *Error for request, HTTP, response-limit, media-type, or JSON
//     failures; otherwise nil.
func (c *Client) postDHCPNoBodyJSON(
	ctx context.Context,
	operation string,
	endpoint string,
	result any,
) *Error {
	response, cancel, requestErr := c.executeGlobalRequest( //nolint:bodyclose // readGlobalResponse closes the body.
		ctx,
		operation,
		http.MethodPost,
		endpoint,
		http.NoBody,
	)
	if requestErr != nil {
		return requestErr
	}

	requestErr = readGlobalJSONResponse(
		operation,
		http.MethodPost,
		response,
		c.maxResponseBytes,
		result,
	)

	cancel()

	return requestErr
}

// dhcpStatusFromWire converts a wire DHCP status into its public model.
//
// Parameters:
//   - wireStatus: The decoded DHCP status response. A nil status or absent
//     leases list is invalid.
//
// Returns:
//   - status: The public DHCP status when all required fields are present.
//   - err: An error identifying a missing required status or lease field.
func dhcpStatusFromWire(wireStatus *dhcpStatusResponse) (*DHCPStatus, error) {
	if wireStatus == nil || wireStatus.Leases == nil {
		return nil, errRequiredDHCPStatusField
	}

	leases, err := dhcpLeasesFromWire(wireStatus.Leases)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	status := &DHCPStatus{
		Enabled:       wireStatus.Enabled,
		InterfaceName: wireStatus.InterfaceName,
		V4:            dhcpConfigV4FromWire(wireStatus.V4),
		V6:            dhcpConfigV6FromWire(wireStatus.V6),
		Leases:        leases,
		StaticLeases:  nil,
	}
	if wireStatus.StaticLeases != nil {
		staticLeases, staticErr := dhcpStaticLeasesFromWire(wireStatus.StaticLeases)
		if staticErr != nil {
			return nil, fmt.Errorf("%w", staticErr)
		}

		status.StaticLeases = &staticLeases
	}

	return status, nil
}

// dhcpLeasesFromWire converts a wire dynamic lease list into public leases.
//
// Parameters:
//   - wireLeases: The decoded dynamic lease list. Every entry must be present.
//
// Returns:
//   - leases: The public dynamic leases when every entry is present.
//   - err: An error identifying the entry with a missing required lease field.
func dhcpLeasesFromWire(wireLeases *[]dhcpLeaseResponse) ([]DHCPLease, error) {
	leases := make([]DHCPLease, 0, len(*wireLeases))
	for index := range *wireLeases {
		lease, err := dhcpLeaseFromWire((*wireLeases)[index])
		if err != nil {
			return nil, fmt.Errorf("leases[%d]: %w", index, err)
		}

		leases = append(leases, lease)
	}

	return leases, nil
}

// dhcpStaticLeasesFromWire converts a wire static lease list into public leases.
//
// Parameters:
//   - wireLeases: The decoded static lease list. Every entry must be present.
//
// Returns:
//   - leases: The public static leases when every entry is present.
//   - err: An error identifying the entry with a missing required static lease
//     field.
func dhcpStaticLeasesFromWire(wireLeases *[]dhcpStaticLeaseResponse) ([]DHCPStaticLease, error) {
	staticLeases := make([]DHCPStaticLease, 0, len(*wireLeases))
	for index := range *wireLeases {
		lease, err := dhcpStaticLeaseFromWire((*wireLeases)[index])
		if err != nil {
			return nil, fmt.Errorf("static_leases[%d]: %w", index, err)
		}

		staticLeases = append(staticLeases, lease)
	}

	return staticLeases, nil
}

// dhcpLeaseFromWire converts one wire dynamic lease into its public model.
//
// Parameters:
//   - wireLease: The decoded dynamic lease. All fields must be present.
//
// Returns:
//   - lease: The public dynamic lease when all fields are present.
//   - err: An error identifying a missing required lease field.
func dhcpLeaseFromWire(wireLease dhcpLeaseResponse) (DHCPLease, error) {
	if wireLease.Expires == nil ||
		wireLease.Hostname == nil ||
		wireLease.IP == nil ||
		wireLease.MAC == nil {

		return DHCPLease{}, errRequiredDHCPLeaseField
	}

	return DHCPLease{
		Expires:  *wireLease.Expires,
		Hostname: *wireLease.Hostname,
		IP:       *wireLease.IP,
		MAC:      *wireLease.MAC,
	}, nil
}

// dhcpStaticLeaseFromWire converts one wire static lease into its public model.
//
// Parameters:
//   - wireLease: The decoded static lease. All fields must be present.
//
// Returns:
//   - lease: The public static lease when all fields are present.
//   - err: An error identifying a missing required static lease field.
func dhcpStaticLeaseFromWire(wireLease dhcpStaticLeaseResponse) (DHCPStaticLease, error) {
	if wireLease.Hostname == nil || wireLease.IP == nil || wireLease.MAC == nil {
		return DHCPStaticLease{}, errRequiredDHCPStaticLease
	}

	return DHCPStaticLease{
		Hostname: *wireLease.Hostname,
		IP:       *wireLease.IP,
		MAC:      *wireLease.MAC,
	}, nil
}

// dhcpConfigV4FromWire converts optional IPv4 response settings into the
// public configuration type.
//
// Parameters:
//   - wireConfig: The decoded IPv4 settings, or nil for an absent or null
//     object.
//
// Returns:
//   - config: The public IPv4 settings, or nil when wireConfig is nil.
func dhcpConfigV4FromWire(wireConfig *dhcpConfigV4Response) *DHCPConfigV4 {
	if wireConfig == nil {
		return nil
	}

	return &DHCPConfigV4{
		GatewayIP:     wireConfig.GatewayIP,
		SubnetMask:    wireConfig.SubnetMask,
		RangeStart:    wireConfig.RangeStart,
		RangeEnd:      wireConfig.RangeEnd,
		LeaseDuration: wireConfig.LeaseDuration,
	}
}

// dhcpConfigV6FromWire converts optional IPv6 response settings into the
// public configuration type.
//
// Parameters:
//   - wireConfig: The decoded IPv6 settings, or nil for an absent or null
//     object.
//
// Returns:
//   - config: The public IPv6 settings, or nil when wireConfig is nil.
func dhcpConfigV6FromWire(wireConfig *dhcpConfigV6Response) *DHCPConfigV6 {
	if wireConfig == nil {
		return nil
	}

	return &DHCPConfigV6{
		RangeStart:    wireConfig.RangeStart,
		LeaseDuration: wireConfig.LeaseDuration,
	}
}

// dhcpInterfacesFromWire converts wire interface objects into public interface
// values.
//
// Parameters:
//   - wireInterfaces: The decoded interfaces keyed by interface name.
//
// Returns:
//   - interfaces: The public interfaces when every required field is present.
//   - err: An error identifying the interface with a missing required field.
func dhcpInterfacesFromWire(
	wireInterfaces map[string]*dhcpInterfaceResponse,
) (map[string]DHCPInterface, error) {
	interfaces := make(map[string]DHCPInterface, len(wireInterfaces))
	for name := range wireInterfaces {
		wireInterface := wireInterfaces[name]
		if wireInterface == nil ||
			wireInterface.Flags == nil ||
			wireInterface.GatewayIP == nil ||
			wireInterface.HardwareAddress == nil ||
			wireInterface.IPv4Addresses == nil ||
			wireInterface.IPv6Addresses == nil ||
			wireInterface.Name == nil {

			return nil, fmt.Errorf("%s: %w", name, errRequiredDHCPInterface)
		}

		interfaces[name] = DHCPInterface{
			Flags:           *wireInterface.Flags,
			GatewayIP:       *wireInterface.GatewayIP,
			HardwareAddress: *wireInterface.HardwareAddress,
			IPv4Addresses:   *wireInterface.IPv4Addresses,
			IPv6Addresses:   *wireInterface.IPv6Addresses,
			Name:            *wireInterface.Name,
		}
	}

	return interfaces, nil
}

// validateDHCPFindResult validates every search status present in an active
// DHCP search result.
//
// Parameters:
//   - result: The decoded active-search result.
//
// Returns:
//   - err: An error identifying an unsupported search status; otherwise nil.
func validateDHCPFindResult(result *DHCPFindResult) error {
	if result.V4 != nil {
		err := validateDHCPFindResultV4(result.V4)
		if err != nil {
			return fmt.Errorf("v4: %w", err)
		}
	}
	if result.V6 != nil {
		err := validateDHCPOtherServer(result.V6.OtherServer)
		if err != nil {
			return fmt.Errorf("v6: %w", err)
		}
	}

	return nil
}

// validateDHCPFindResultV4 validates every search status in an IPv4 search
// result.
//
// Parameters:
//   - result: The decoded IPv4 search result.
//
// Returns:
//   - err: An error identifying an unsupported search status; otherwise nil.
func validateDHCPFindResultV4(result *DHCPFindResultV4) error {
	err := validateDHCPOtherServer(result.OtherServer)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = validateDHCPStaticIP(result.StaticIP)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// validateDHCPOtherServer validates an optional other-server search result.
//
// Parameters:
//   - result: The decoded other-server result, or nil for an absent result.
//
// Returns:
//   - err: An error identifying an unsupported search status; otherwise nil.
func validateDHCPOtherServer(result *DHCPOtherServerResult) error {
	if result == nil || result.Found == nil {
		return nil
	}
	if !validDHCPSearchStatus(*result.Found) {
		return errInvalidDHCPSearchStatus
	}

	return nil
}

// validateDHCPStaticIP validates an optional static-IP search result.
//
// Parameters:
//   - result: The decoded static-IP result, or nil for an absent result.
//
// Returns:
//   - err: An error identifying an unsupported search status; otherwise nil.
func validateDHCPStaticIP(result *DHCPStaticIPResult) error {
	if result == nil || result.Status == nil {
		return nil
	}
	if !validDHCPSearchStatus(*result.Status) {
		return errInvalidDHCPSearchStatus
	}

	return nil
}

// validDHCPSearchStatus reports whether status is a documented active-search
// status.
//
// Parameters:
//   - status: The status to validate.
//
// Returns:
//   - valid: Whether status is one of the documented search status constants.
func validDHCPSearchStatus(status DHCPSearchStatus) bool {
	switch status {
	case DHCPSearchStatusYes, DHCPSearchStatusNo, DHCPSearchStatusError:
		return true
	default:
		return false
	}
}

// dhcpJSONError creates a structured DHCP JSON decoding or validation error.
//
// Parameters:
//   - operation: The operation name placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The decoding or validation cause.
//
// Returns:
//   - err: The structured JSON error.
func dhcpJSONError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}
