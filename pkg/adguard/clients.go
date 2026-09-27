// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"
)

// ClientsService manages configured and discovered client records.
type ClientsService interface {
	ClientsStatus(ctx context.Context) (*ClientsStatus, error)
	ClientsAdd(ctx context.Context, config ClientConfig) error
	ClientsDelete(ctx context.Context, request ClientDelete) error
	ClientsUpdate(ctx context.Context, request ClientUpdate) error
	ClientsSearch(ctx context.Context, request ClientsSearchRequest) ([]ClientFindEntry, error)

	// Deprecated: Use ClientsSearch with a ClientsSearchRequest instead.
	ClientsFind(ctx context.Context, ids ...string) ([]ClientFindEntry, error)
}

// AccessListService manages global client and blocked-host access rules.
type AccessListService interface {
	AccessList(ctx context.Context) (*AccessList, error)
	AccessSet(ctx context.Context, access AccessList) error
}

// SafeSearchConfig contains safe-search provider settings.
//
// Every field is optional. Nil pointers represent an absent or null value,
// while nonnil pointers preserve explicit false values and other zero values.
type SafeSearchConfig struct {
	// Enabled optionally controls safe search for all supported providers.
	Enabled *bool `json:"enabled,omitempty"`
	// Bing optionally controls safe search for Bing.
	Bing *bool `json:"bing,omitempty"`
	// DuckDuckGo optionally controls safe search for DuckDuckGo.
	DuckDuckGo *bool `json:"duckduckgo,omitempty"`
	// Ecosia optionally controls safe search for Ecosia.
	Ecosia *bool `json:"ecosia,omitempty"`
	// Google optionally controls safe search for Google.
	Google *bool `json:"google,omitempty"`
	// Pixabay optionally controls safe search for Pixabay.
	Pixabay *bool `json:"pixabay,omitempty"`
	// Yandex optionally controls safe search for Yandex.
	Yandex *bool `json:"yandex,omitempty"`
	// YouTube optionally controls safe search for YouTube.
	YouTube *bool `json:"youtube,omitempty"`
}

// ClientConfig contains the configuration of a named AdGuard client.
//
// ClientsAdd requires a nonempty Name and at least one ID. For add requests,
// false-valued booleans and a zero UpstreamsCacheSize are omitted, while true
// booleans and nonzero cache sizes are sent. The same value type is used for
// response decoding, where false and zero remain meaningful ordinary values.
type ClientConfig struct {
	// Name is the client name. ClientsAdd requires it to contain non-whitespace text.
	Name string `json:"name,omitempty"`
	// IDs contains the client identifiers. ClientsAdd requires at least one ID;
	// nil and empty lists are omitted from add requests.
	IDs []string `json:"ids,omitempty"`
	// UseGlobalSettings reports or requests use of global client settings.
	// ClientsAdd omits false and sends only true.
	UseGlobalSettings bool `json:"use_global_settings,omitempty"`
	// FilteringEnabled reports or requests per-client filtering.
	// ClientsAdd omits false and sends only true.
	FilteringEnabled bool `json:"filtering_enabled,omitempty"`
	// ParentalEnabled reports or requests per-client parental control.
	// ClientsAdd omits false and sends only true.
	ParentalEnabled bool `json:"parental_enabled,omitempty"`
	// SafebrowsingEnabled reports or requests per-client safe browsing.
	// ClientsAdd omits false and sends only true.
	SafebrowsingEnabled bool `json:"safebrowsing_enabled,omitempty"`
	// SafesearchEnabled reports or requests per-client safe search.
	// ClientsAdd omits false and sends only true.
	SafesearchEnabled bool `json:"safesearch_enabled,omitempty"`
	// SafeSearch optionally contains provider-specific safe-search settings.
	// Nil omits the object, while a nonnil zero value sends an object whose
	// provider fields are themselves omitted.
	SafeSearch *SafeSearchConfig `json:"safe_search,omitempty"`
	// UseGlobalBlockedServices reports or requests use of global blocked services.
	// ClientsAdd omits false and sends only true.
	UseGlobalBlockedServices bool `json:"use_global_blocked_services,omitempty"`
	// BlockedServicesSchedule contains the blocked-services schedule. Nil and
	// empty maps are omitted from add requests; response decoding distinguishes
	// absent or null from an explicitly empty map.
	BlockedServicesSchedule map[string]any `json:"blocked_services_schedule,omitempty"`
	// BlockedServices contains blocked-service identifiers. Nil and empty lists
	// are omitted from add requests; response decoding preserves the distinction.
	BlockedServices []string `json:"blocked_services,omitempty"`
	// Upstreams contains client-specific DNS upstreams. Nil and empty lists are
	// omitted from add requests; response decoding preserves the distinction.
	Upstreams []string `json:"upstreams,omitempty"`
	// Tags contains the client's tags. Nil and empty lists are omitted from add
	// requests; response decoding preserves the distinction.
	Tags []string `json:"tags,omitempty"`
	// IgnoreQuerylog reports or requests exclusion from the query log.
	// ClientsAdd omits false and sends only true.
	IgnoreQuerylog bool `json:"ignore_querylog,omitempty"`
	// IgnoreStatistics reports or requests exclusion from statistics.
	// ClientsAdd omits false and sends only true.
	IgnoreStatistics bool `json:"ignore_statistics,omitempty"`
	// UpstreamsCacheEnabled reports or requests the client upstream cache.
	// ClientsAdd omits false and sends only true.
	UpstreamsCacheEnabled bool `json:"upstreams_cache_enabled,omitempty"`
	// UpstreamsCacheSize reports or requests the client upstream cache size.
	// ClientsAdd omits zero and sends only nonzero values.
	UpstreamsCacheSize int64 `json:"upstreams_cache_size,omitempty"`
}

// clientConfigRequest preserves add-request presence semantics.
type clientConfigRequest struct {
	Name                     string            `json:"name,omitempty"`
	IDs                      []string          `json:"ids,omitempty"`
	UseGlobalSettings        optionalTrue      `json:"use_global_settings,omitzero"`
	FilteringEnabled         optionalTrue      `json:"filtering_enabled,omitzero"`
	ParentalEnabled          optionalTrue      `json:"parental_enabled,omitzero"`
	SafebrowsingEnabled      optionalTrue      `json:"safebrowsing_enabled,omitzero"`
	SafesearchEnabled        optionalTrue      `json:"safesearch_enabled,omitzero"`
	SafeSearch               *SafeSearchConfig `json:"safe_search,omitempty"`
	UseGlobalBlockedServices optionalTrue      `json:"use_global_blocked_services,omitzero"`
	BlockedServicesSchedule  map[string]any    `json:"blocked_services_schedule,omitempty"`
	BlockedServices          []string          `json:"blocked_services,omitempty"`
	Upstreams                []string          `json:"upstreams,omitempty"`
	Tags                     []string          `json:"tags,omitempty"`
	IgnoreQuerylog           optionalTrue      `json:"ignore_querylog,omitzero"`
	IgnoreStatistics         optionalTrue      `json:"ignore_statistics,omitzero"`
	UpstreamsCacheEnabled    optionalTrue      `json:"upstreams_cache_enabled,omitzero"`
	UpstreamsCacheSize       *int64            `json:"upstreams_cache_size,omitempty"`
}

// optionalTrue serializes true and omits false.
type optionalTrue bool

// ClientAuto describes a client discovered by AdGuard Home.
//
// A nil WhoisInfo map represents an absent or null value, while a nonnil empty
// map represents an explicitly empty object.
type ClientAuto struct {
	// IP is the discovered client's IP address.
	IP string `json:"ip,omitempty"`
	// Name is the discovered client's name.
	Name string `json:"name,omitempty"`
	// Source is the discovery source reported by AdGuard Home.
	Source string `json:"source,omitempty"`
	// WhoisInfo contains optional WHOIS information keyed by field name.
	WhoisInfo map[string]string `json:"whois_info,omitempty"`
}

// ClientsStatus contains configured and automatically discovered clients.
//
// Nil slices represent absent or null fields, while nonnil empty slices
// represent explicitly empty lists.
type ClientsStatus struct {
	// Clients contains the configured clients.
	Clients []ClientConfig `json:"clients,omitempty"`
	// AutoClients contains the automatically discovered clients.
	AutoClients []ClientAuto `json:"auto_clients,omitempty"`
	// SupportedTags contains the client tags supported by AdGuard Home.
	SupportedTags []string `json:"supported_tags,omitempty"`
}

// ClientDelete identifies a client to remove.
type ClientDelete struct {
	// Name identifies the configured client. ClientsDelete requires non-whitespace text.
	Name string `json:"name,omitempty"`
}

// ClientUpdateData is a presence-sensitive client update patch.
//
// Nil pointer fields are omitted. Nonnil pointers preserve explicit JSON values,
// including false, zero, empty strings, empty lists, and empty objects.
type ClientUpdateData struct {
	// Name optionally changes the client name when set, including to an empty
	// string.
	Name *string `json:"name,omitzero"`
	// IDs optionally replaces the client identifiers. Nil omits the field, and a
	// nonnil pointer sends an array, including an empty array for an empty slice.
	IDs *[]string `json:"ids,omitzero"`
	// UseGlobalSettings optionally sets use of global client settings.
	UseGlobalSettings *bool `json:"use_global_settings,omitzero"`
	// FilteringEnabled optionally sets per-client filtering.
	FilteringEnabled *bool `json:"filtering_enabled,omitzero"`
	// ParentalEnabled optionally sets per-client parental control.
	ParentalEnabled *bool `json:"parental_enabled,omitzero"`
	// SafebrowsingEnabled optionally sets per-client safe browsing.
	SafebrowsingEnabled *bool `json:"safebrowsing_enabled,omitzero"`
	// SafesearchEnabled optionally sets per-client safe search.
	SafesearchEnabled *bool `json:"safesearch_enabled,omitzero"`
	// SafeSearch optionally replaces provider-specific safe-search settings.
	// Nil omits the object, while a nonnil zero value sends an empty object.
	SafeSearch *SafeSearchConfig `json:"safe_search,omitzero"`
	// UseGlobalBlockedServices optionally sets use of global blocked services.
	UseGlobalBlockedServices *bool `json:"use_global_blocked_services,omitzero"`
	// BlockedServicesSchedule optionally replaces the blocked-services schedule.
	// Nil omits the field, and a nonnil pointer sends an object, including an
	// empty object for an empty map.
	BlockedServicesSchedule *map[string]any `json:"blocked_services_schedule,omitzero"`
	// BlockedServices optionally replaces blocked-service identifiers. Nil omits
	// the field, and a nonnil pointer sends an array, including an empty array
	// for an empty slice.
	BlockedServices *[]string `json:"blocked_services,omitzero"`
	// Upstreams optionally replaces DNS upstreams. Nil omits the field, and a
	// nonnil pointer sends an array, including an empty array for an empty slice.
	Upstreams *[]string `json:"upstreams,omitzero"`
	// Tags optionally replaces client tags. Nil omits the field, and a nonnil
	// pointer sends an array, including an empty array for an empty slice.
	Tags *[]string `json:"tags,omitzero"`
	// IgnoreQuerylog optionally sets exclusion from the query log.
	IgnoreQuerylog *bool `json:"ignore_querylog,omitzero"`
	// IgnoreStatistics optionally sets exclusion from statistics.
	IgnoreStatistics *bool `json:"ignore_statistics,omitzero"`
	// UpstreamsCacheEnabled optionally sets the client upstream cache.
	UpstreamsCacheEnabled *bool `json:"upstreams_cache_enabled,omitzero"`
	// UpstreamsCacheSize optionally sets the client upstream cache size.
	// A nonnil pointer sends zero explicitly.
	UpstreamsCacheSize *int64 `json:"upstreams_cache_size,omitzero"`
}

// ClientUpdate identifies a client and supplies a presence-sensitive patch.
type ClientUpdate struct {
	// Name identifies the configured client to update. It must contain
	// non-whitespace text, but the original untrimmed value is sent.
	Name string `json:"name,omitempty"`
	// Data contains the fields to patch. ClientsUpdate requires a nonnil value.
	Data *ClientUpdateData `json:"data,omitzero"`
}

// ClientsSearchRequestItem identifies one client search input.
type ClientsSearchRequestItem struct {
	// ID is the identifier to match. ClientsSearch requires non-whitespace text.
	ID string `json:"id,omitempty"`
}

// ClientsSearchRequest contains exact-match client search inputs.
//
// Nil and empty Clients slices are both encoded as an empty JSON object. Every
// present item must contain a non-whitespace ID.
type ClientsSearchRequest struct {
	// Clients contains the identifiers to search for.
	Clients []ClientsSearchRequestItem `json:"clients,omitempty"`
}

// ClientFindInfo contains the settings returned for a matched client.
//
// Nil slices and maps represent absent or null values, while nonnil empty values
// represent explicitly empty lists or objects.
type ClientFindInfo struct {
	// Name is the matched client's name.
	Name string `json:"name,omitempty"`
	// IDs contains the matched client's identifiers.
	IDs []string `json:"ids,omitempty"`
	// UseGlobalSettings reports whether the client uses global settings.
	UseGlobalSettings bool `json:"use_global_settings,omitempty"`
	// FilteringEnabled reports whether filtering is enabled for the client.
	FilteringEnabled bool `json:"filtering_enabled,omitempty"`
	// ParentalEnabled reports whether parental control is enabled for the client.
	ParentalEnabled bool `json:"parental_enabled,omitempty"`
	// SafebrowsingEnabled reports whether safe browsing is enabled for the client.
	SafebrowsingEnabled bool `json:"safebrowsing_enabled,omitempty"`
	// SafesearchEnabled reports whether safe search is enabled for the client.
	SafesearchEnabled bool `json:"safesearch_enabled,omitempty"`
	// SafeSearch optionally contains provider-specific safe-search settings.
	SafeSearch *SafeSearchConfig `json:"safe_search,omitempty"`
	// UseGlobalBlockedServices reports whether the client uses global blocked services.
	UseGlobalBlockedServices bool `json:"use_global_blocked_services,omitempty"`
	// BlockedServices contains blocked-service identifiers.
	BlockedServices []string `json:"blocked_services,omitempty"`
	// Upstreams contains client-specific DNS upstreams.
	Upstreams []string `json:"upstreams,omitempty"`
	// WhoisInfo contains WHOIS information keyed by field name.
	WhoisInfo map[string]string `json:"whois_info,omitempty"`
	// Disallowed reports whether the client is disallowed.
	Disallowed bool `json:"disallowed,omitempty"`
	// DisallowedRule contains the rule that disallowed the client.
	DisallowedRule string `json:"disallowed_rule,omitempty"`
	// IgnoreQuerylog reports whether the client is excluded from the query log.
	IgnoreQuerylog bool `json:"ignore_querylog,omitempty"`
	// IgnoreStatistics reports whether the client is excluded from statistics.
	IgnoreStatistics bool `json:"ignore_statistics,omitempty"`
}

// ClientFindEntry maps a requested identifier to its matched client.
//
// A nil map represents an absent or null value, while a nonnil empty map
// represents an explicitly empty object.
type ClientFindEntry map[string]ClientFindInfo

// AccessList contains allowlist, blocklist, and blocked-host entries.
//
// Response decoding preserves nil for an absent or null list and a nonnil empty
// slice for an explicitly empty list. AccessSet omits both nil and empty slices,
// so an explicit empty list cannot be expressed by the current request contract.
type AccessList struct {
	// AllowedClients contains client identifiers that bypass filtering.
	AllowedClients []string `json:"allowed_clients,omitempty"`
	// DisallowedClients contains client identifiers subject to blocked filtering.
	DisallowedClients []string `json:"disallowed_clients,omitempty"`
	// BlockedHosts contains hostnames blocked for all clients.
	BlockedHosts []string `json:"blocked_hosts,omitempty"`
}

// clientsResponseMode describes how a successful client response is interpreted.
type clientsResponseMode uint8

const (
	// ClientsResponseBody accepts any successful response body.
	clientsResponseBody clientsResponseMode = iota
	// ClientsResponseJSON requires a JSON content type.
	clientsResponseJSON
)

var (
	// ErrClientNameRequired indicates that a client name is missing.
	errClientNameRequired = errors.New("client name is required")
	// ErrClientIDsRequired indicates that a client has no identifiers.
	errClientIDsRequired = errors.New("at least one client ID is required")
	// ErrClientDataRequired indicates that a client update has no patch data.
	errClientDataRequired = errors.New("client update data is required")
	// ErrClientSearchIDRequired indicates that a client search identifier is missing.
	errClientSearchIDRequired = errors.New("client search ID is required")
	// ErrAccessDuplicate indicates that an access list contains duplicates.
	errAccessDuplicate = errors.New("access list contains duplicate entries")
	// ErrAccessOverlap indicates that allowed and disallowed clients overlap.
	errAccessOverlap = errors.New("allowed and disallowed client lists overlap")
	// ErrClientRequestBody indicates that a request body could not be encoded.
	errClientRequestBody = errors.New("encode request body")
	// ErrClientJSONResponse indicates that a client response could not be decoded.
	errClientJSONResponse = errors.New("decode client response")
	// ErrClientUnexpectedJSONType indicates that a JSON response has another content type.
	errClientUnexpectedJSONType = errors.New("content type must be application/json")
)

var (
	_ ClientsService    = (*Client)(nil)
	_ AccessListService = (*Client)(nil)
)

// newClientConfigRequest converts a public client configuration into its add-request representation.
//
// Parameters:
//   - config: The client configuration to convert.
//
// Returns:
//   - The presence-sensitive request representation.
func newClientConfigRequest(config ClientConfig) clientConfigRequest {
	request := clientConfigRequest{
		Name:                     config.Name,
		IDs:                      config.IDs,
		SafeSearch:               config.SafeSearch,
		BlockedServicesSchedule:  config.BlockedServicesSchedule,
		BlockedServices:          config.BlockedServices,
		Upstreams:                config.Upstreams,
		Tags:                     config.Tags,
		UseGlobalSettings:        optionalTrue(config.UseGlobalSettings),
		FilteringEnabled:         optionalTrue(config.FilteringEnabled),
		ParentalEnabled:          optionalTrue(config.ParentalEnabled),
		SafebrowsingEnabled:      optionalTrue(config.SafebrowsingEnabled),
		SafesearchEnabled:        optionalTrue(config.SafesearchEnabled),
		UseGlobalBlockedServices: optionalTrue(config.UseGlobalBlockedServices),
		IgnoreQuerylog:           optionalTrue(config.IgnoreQuerylog),
		IgnoreStatistics:         optionalTrue(config.IgnoreStatistics),
		UpstreamsCacheEnabled:    optionalTrue(config.UpstreamsCacheEnabled),
		UpstreamsCacheSize:       nil,
	}
	if config.UpstreamsCacheSize != 0 {
		request.UpstreamsCacheSize = &config.UpstreamsCacheSize
	}

	return request
}

// ClientsStatus retrieves configured and automatically discovered clients.
//
// Nil response slices represent absent or null fields, while nonnil empty slices
// represent explicitly empty lists.
//
// Parameters:
//   - ctx: The request context.
//
// Returns:
//   - The client status, or a client error when the request fails, the bounded
//     response is not JSON, or the top-level response is null or malformed.
func (c *Client) ClientsStatus(ctx context.Context) (*ClientsStatus, error) {
	operation := "clients_status"
	body, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodGet,
		"control/clients",
		nil,
		clientsResponseJSON,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var response ClientsStatus

	err := json.Unmarshal(body, &response)
	if err != nil {
		return nil, clientJSONError(operation, http.MethodGet, fmt.Errorf("%w: %w", errClientJSONResponse, err))
	}

	return &response, nil
}

// ClientsAdd adds a configured client.
//
// Name must contain non-whitespace text and IDs must contain at least one
// identifier. False-valued booleans and a zero UpstreamsCacheSize are omitted
// from the add request; true booleans and nonzero cache sizes are sent.
//
// Parameters:
//   - ctx: The request context.
//   - config: The configured client to add.
//
// Returns:
//   - An error when validation, request encoding, bounded response reading, or
//     response status validation fails.
func (c *Client) ClientsAdd(ctx context.Context, config ClientConfig) error {
	operation := "clients_add"
	err := validateClientConfig(config)
	if err != nil {
		return clientValidationError(operation, err)
	}

	_, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodPost,
		"control/clients/add",
		newClientConfigRequest(config),
		clientsResponseBody,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ClientsDelete removes a configured client by name.
//
// The name is validated after trimming whitespace, but the original untrimmed
// value is sent when it is valid.
//
// Parameters:
//   - ctx: The request context.
//   - request: The configured client name to remove.
//
// Returns:
//   - An error when validation, request encoding, bounded response reading, or
//     response status validation fails.
func (c *Client) ClientsDelete(ctx context.Context, request ClientDelete) error {
	operation := "clients_delete"
	if strings.TrimSpace(request.Name) == "" {
		return clientValidationError(operation, errClientNameRequired)
	}

	_, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodPost,
		"control/clients/delete",
		request,
		clientsResponseBody,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ClientsUpdate applies a presence-sensitive patch to a configured client.
//
// The target Name must contain non-whitespace text, and Data must be nonnil.
// Nil patch fields are omitted. Nonnil pointers preserve explicit false, zero,
// empty strings, and empty collection values.
//
// Parameters:
//   - ctx: The request context.
//   - request: The target client and its update patch.
//
// Returns:
//   - An error when validation, request encoding, bounded response reading, or
//     response status validation fails.
func (c *Client) ClientsUpdate(ctx context.Context, request ClientUpdate) error {
	operation := "clients_update"
	if strings.TrimSpace(request.Name) == "" {
		return clientValidationError(operation, errClientNameRequired)
	}
	if request.Data == nil {
		return clientValidationError(operation, errClientDataRequired)
	}

	_, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodPost,
		"control/clients/update",
		request,
		clientsResponseBody,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ClientsSearch performs an exact-match client search.
//
// Every present search item must contain a non-whitespace ID. Nil and empty
// Clients slices are both encoded as an empty JSON object.
//
// Parameters:
//   - ctx: The request context.
//   - request: The exact-match search inputs.
//
// Returns:
//   - The matched-client entries, including a nonnil empty slice for an empty
//     JSON array, or a client error when validation, transport, response
//     validation, or JSON decoding fails.
func (c *Client) ClientsSearch(ctx context.Context, request ClientsSearchRequest) ([]ClientFindEntry, error) {
	operation := "clients_search"

	for _, item := range request.Clients {
		if strings.TrimSpace(item.ID) == "" {
			return nil, clientValidationError(operation, errClientSearchIDRequired)
		}
	}

	body, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodPost,
		"control/clients/search",
		request,
		clientsResponseJSON,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var response []ClientFindEntry

	err := json.Unmarshal(body, &response)
	if err != nil {
		return nil, clientJSONError(operation, http.MethodPost, fmt.Errorf("%w: %w", errClientJSONResponse, err))
	}

	return response, nil
}

// ClientsFind performs the deprecated query-parameter client lookup.
//
// Identifiers are sent in order as the ip0, ip1, and subsequent query
// parameters. The identifiers are not otherwise validated by the client.
//
// Parameters:
//   - ctx: The request context.
//   - ids: The identifiers to look up.
//
// Returns:
//   - The matched-client entries, including a nonnil empty slice for an empty
//     JSON array, or a client error when transport, response validation, or JSON
//     decoding fails.
//
// Deprecated: Use ClientsSearch with a ClientsSearchRequest instead.
func (c *Client) ClientsFind(ctx context.Context, ids ...string) ([]ClientFindEntry, error) {
	operation := "clients_find"
	query := make(url.Values, len(ids))

	for index, id := range ids {
		query.Set(fmt.Sprintf("ip%d", index), id)
	}

	endpoint := "control/clients/find?" + query.Encode()
	body, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodGet,
		endpoint,
		nil,
		clientsResponseJSON,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var response []ClientFindEntry

	err := json.Unmarshal(body, &response)
	if err != nil {
		return nil, clientJSONError(operation, http.MethodGet, fmt.Errorf("%w: %w", errClientJSONResponse, err))
	}

	return response, nil
}

// AccessList retrieves the current client and host access list.
//
// Nil response slices represent absent or null fields, while nonnil empty slices
// represent explicitly empty lists.
//
// Parameters:
//   - ctx: The request context.
//
// Returns:
//   - The access list, or a client error when the request fails, the bounded
//     response is not JSON, or the top-level response is null or malformed.
func (c *Client) AccessList(ctx context.Context) (*AccessList, error) {
	operation := "access_list"
	body, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodGet,
		"control/access/list",
		nil,
		clientsResponseJSON,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	var response AccessList

	err := json.Unmarshal(body, &response)
	if err != nil {
		return nil, clientJSONError(operation, http.MethodGet, fmt.Errorf("%w: %w", errClientJSONResponse, err))
	}

	return &response, nil
}

// AccessSet replaces the current client and host access list.
//
// The request rejects duplicate entries within any list and rejects client IDs
// that occur in both the allowed and disallowed lists. Nil and nonnil empty
// slices are both omitted, so the current contract cannot express an explicit
// empty list.
//
// Parameters:
//   - ctx: The request context.
//   - access: The access-list replacement to send.
//
// Returns:
//   - An error when validation, request encoding, bounded response reading, or
//     response status validation fails.
func (c *Client) AccessSet(ctx context.Context, access AccessList) error {
	operation := "access_set"
	err := validateAccessList(access)
	if err != nil {
		return clientValidationError(operation, err)
	}

	_, requestErr := c.doClientsRequest(
		ctx,
		operation,
		http.MethodPost,
		"control/access/set",
		access,
		clientsResponseBody,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// validateClientConfig validates fields required to add a client.
//
// Parameters:
//   - config: The client configuration to validate.
//
// Returns:
//   - A validation error when a required field is missing.
func validateClientConfig(config ClientConfig) error {
	if strings.TrimSpace(config.Name) == "" {
		return errClientNameRequired
	}
	if len(config.IDs) == 0 {
		return errClientIDsRequired
	}

	return nil
}

// validateAccessList rejects duplicate and overlapping access entries.
//
// Parameters:
//   - access: The access list to validate.
//
// Returns:
//   - A validation error when the list is internally inconsistent.
func validateAccessList(access AccessList) error {
	if hasDuplicates(access.AllowedClients) ||
		hasDuplicates(access.DisallowedClients) ||
		hasDuplicates(access.BlockedHosts) {

		return errAccessDuplicate
	}

	allowed := make(map[string]struct{}, len(access.AllowedClients))
	for _, clientID := range access.AllowedClients {
		allowed[clientID] = struct{}{}
	}

	for _, clientID := range access.DisallowedClients {
		if _, ok := allowed[clientID]; ok {
			return errAccessOverlap
		}
	}

	return nil
}

// hasDuplicates reports whether values contains a duplicate.
//
// Parameters:
//   - values: The values to inspect.
//
// Returns:
//   - Whether any value occurs more than once.
func hasDuplicates(values []string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			return true
		}

		seen[value] = struct{}{}
	}

	return false
}

// doClientsRequest creates, executes, and reads a client API request.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The public operation name used in errors.
//   - method: The HTTP method used in errors.
//   - endpoint: The endpoint path and optional query string.
//   - requestBody: The optional request body.
//   - mode: The successful response interpretation mode.
//
// Returns:
//   - The bounded response body or a client error.
func (c *Client) doClientsRequest(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	requestBody any,
	mode clientsResponseMode,
) ([]byte, *Error) {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)
	defer cancel()

	request, requestErr := c.newClientsRequest(
		requestContext,
		operation,
		method,
		endpoint,
		requestBody,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	response, requestErr := c.executeClientsRequest(requestContext, operation, method, request)
	if requestErr != nil {
		return nil, requestErr
	}

	body, tooLarge, readErr := readBounded(response.Body, c.maxResponseBytes)
	closeErr := response.Body.Close()
	bodyErr := clientsResponseBodyError(
		operation,
		method,
		response,
		c.maxResponseBytes,
		tooLarge,
		readErr,
		closeErr,
	)
	if bodyErr != nil {
		return nil, bodyErr
	}

	return validateClientsResponse(operation, method, response, body, mode)
}

// newClientsRequest builds an authenticated client API request.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The public operation name used in errors.
//   - method: The HTTP method.
//   - endpoint: The endpoint path and optional query string.
//   - requestBody: The optional request body.
//
// Returns:
//   - The prepared request or a client error.
func (c *Client) newClientsRequest(
	ctx context.Context,
	operation string,
	method string,
	endpoint string,
	requestBody any,
) (*http.Request, *Error) {
	endpointPath, rawQuery, hasQuery := strings.Cut(endpoint, "?")
	requestURL := c.endpoint(endpointPath)
	if hasQuery {
		requestURL.RawQuery = rawQuery
	}
	var reader *bytes.Reader

	if requestBody == nil {
		reader = bytes.NewReader(nil)
	} else {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return nil, clientRequestError(operation, method, fmt.Errorf("%w: %w", errClientRequestBody, err))
		}

		reader = bytes.NewReader(encoded)
	}

	request, err := http.NewRequestWithContext(ctx, method, requestURL.String(), reader)
	if err != nil {
		return nil, clientRequestError(operation, method, fmt.Errorf("%w: %w", errCreateRequest, err))
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", jsonContentType)
	}

	request.Header.Set("Accept", jsonContentType)
	request.Header.Set("User-Agent", c.userAgent)

	if c.basicAuth {
		request.SetBasicAuth(c.username, c.password)
	}

	return request, nil
}

// executeClientsRequest executes a prepared client API request.
//
// Parameters:
//   - ctx: The request context.
//   - operation: The public operation name used in errors.
//   - method: The HTTP method used in errors.
//   - request: The prepared request.
//
// Returns:
//   - The HTTP response or a client error.
func (c *Client) executeClientsRequest(
	ctx context.Context,
	operation string,
	method string,
	request *http.Request,
) (*http.Response, *Error) {
	response, err := c.httpClient.Do(request)
	if err == nil {
		return response, nil
	}

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
	clientErr.Method = method
	clientErr.Location = location
	clientErr.Err = cause

	return nil, clientErr
}

// clientsResponseBodyError translates bounded-body read and close failures.
//
// Parameters:
//   - operation: The public operation name used in errors.
//   - method: The HTTP method used in errors.
//   - response: The HTTP response being consumed.
//   - limit: The maximum response body size in bytes.
//   - tooLarge: Whether the body exceeded limit.
//   - readErr: The body read error, if any.
//   - closeErr: The body close error, if any.
//
// Returns:
//   - A client error or nil when reading and closing succeeded.
func clientsResponseBodyError(
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
		clientErr := responseError(operation, ErrorKindResponseTooLarge, response, nil)

		clientErr.Method = method
		clientErr.Limit = limit

		return clientErr
	case readErr != nil:
		clientErr := responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errReadResponse, readErr),
		)

		clientErr.Method = method

		return clientErr
	case closeErr != nil:
		clientErr := responseError(
			operation,
			ErrorKindResponseBody,
			response,
			fmt.Errorf("%w: %w", errCloseResponse, closeErr),
		)

		clientErr.Method = method

		return clientErr
	default:
		return nil
	}
}

// validateClientsResponse validates a bounded client API response.
//
// Parameters:
//   - operation: The public operation name used in errors.
//   - method: The HTTP method used in errors.
//   - response: The HTTP response to validate.
//   - body: The bounded response body.
//   - mode: The successful response interpretation mode.
//
// Returns:
//   - The validated response body or a client error.
func validateClientsResponse(
	operation string,
	method string,
	response *http.Response,
	body []byte,
	mode clientsResponseMode,
) ([]byte, *Error) {
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		clientErr := statusError(
			operation,
			method,
			response.StatusCode,
			response.Status,
			response.Header.Get("Content-Type"),
			body,
		)

		return nil, clientErr
	}
	if mode == clientsResponseBody {
		return body, nil
	}

	clientErr := validateClientsJSONContentType(operation, method, response)
	if clientErr != nil {
		return nil, clientErr
	}
	if mode == clientsResponseJSON && bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return nil, clientJSONError(operation, method, errClientJSONResponse)
	}

	return body, nil
}

// validateClientsJSONContentType validates a successful JSON response content type.
//
// Parameters:
//   - operation: The public operation name used in errors.
//   - method: The HTTP method used in errors.
//   - response: The successful HTTP response.
//
// Returns:
//   - A content-type client error or nil when the media type is JSON.
func validateClientsJSONContentType(operation, method string, response *http.Response) *Error {
	contentType := response.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		clientErr := responseError(
			operation,
			ErrorKindContentType,
			response,
			fmt.Errorf("%w: %w", errParseContentType, err),
		)

		clientErr.Method = method

		return clientErr
	}
	if !strings.EqualFold(mediaType, jsonContentType) {
		clientErr := responseError(
			operation,
			ErrorKindContentType,
			response,
			fmt.Errorf("%w: %s", errClientUnexpectedJSONType, mediaType),
		)

		clientErr.Method = method

		return clientErr
	}

	return nil
}

// clientRequestError creates a request error with operation context.
//
// Parameters:
//   - operation: The public operation name.
//   - method: The HTTP method.
//   - cause: The underlying request error.
//
// Returns:
//   - The client request error.
func clientRequestError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindRequest)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}

// clientJSONError creates a JSON decoding error with operation context.
//
// Parameters:
//   - operation: The public operation name.
//   - method: The HTTP method.
//   - cause: The underlying decoding error.
//
// Returns:
//   - The client JSON error.
func clientJSONError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}

// clientValidationError creates a POST validation error with operation context.
//
// Parameters:
//   - operation: The public operation name.
//   - cause: The underlying validation error.
//
// Returns:
//   - The client configuration error.
func clientValidationError(operation string, cause error) *Error {
	clientErr := newError(ErrorKindConfig)

	clientErr.Operation = operation
	clientErr.Method = http.MethodPost
	clientErr.Err = cause

	return clientErr
}
