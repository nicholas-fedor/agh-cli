// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
)

// BlockedServicesService exposes the current blocked-service catalog and schedule.
type BlockedServicesService interface {
	BlockedServicesAll(ctx context.Context) (*BlockedServicesAll, error)
	BlockedServicesSchedule(ctx context.Context) (*BlockedServicesSchedule, error)
	BlockedServicesScheduleUpdate(ctx context.Context, schedule BlockedServicesSchedule) error

	// Deprecated: Use BlockedServicesAll instead.
	BlockedServicesAvailableServices(ctx context.Context) ([]string, error)
	// Deprecated: Use BlockedServicesSchedule instead.
	BlockedServicesList(ctx context.Context) ([]string, error)
	// Deprecated: Use BlockedServicesScheduleUpdate instead.
	BlockedServicesSet(ctx context.Context, services []string) error
}

// BlockedServicesAll contains the complete blocked-service catalog.
//
// BlockedServices and Groups are required by the response contract. A required
// field that is absent or null produces a JSON error; an explicitly empty list
// is retained.
type BlockedServicesAll struct {
	// BlockedServices contains the services available for blocking.
	BlockedServices []BlockedService `json:"blocked_services"`
	// Groups contains the service groups referenced by the catalog.
	Groups []ServiceGroup `json:"groups"`
}

// BlockedService describes one service available for blocking.
//
// IconSVG, ID, Name, and Rules are required response fields. GroupID is optional;
// nil represents an absent or null value.
type BlockedService struct {
	// IconSVG is the Base64-encoded SVG icon for the service.
	IconSVG string `json:"icon_svg"`
	// ID is the service identifier.
	ID string `json:"id"`
	// Name is the human-readable service name.
	Name string `json:"name"`
	// Rules contains the service's filtering rules.
	Rules []string `json:"rules"`
	// GroupID is the optional group identifier.
	GroupID *string `json:"group_id,omitzero"`
}

// ServiceGroup identifies a group of blocked services.
type ServiceGroup struct {
	// ID is the service-group identifier.
	ID string `json:"id"`
}

// BlockedServicesSchedule contains the blocked-service identifiers and schedule.
//
// Both fields are optional. Nil represents an absent or null value. A nonnil
// pointer to an empty slice or schedule preserves an explicitly empty value in
// an update request.
type BlockedServicesSchedule struct {
	// Schedule optionally contains the days and time zone for blocking.
	Schedule *Schedule `json:"schedule,omitzero"`
	// IDs optionally contains the blocked-service identifiers.
	IDs *[]string `json:"ids,omitzero"`
}

// Schedule contains the weekly blocked-service schedule.
//
// Every field is optional. Nil represents an absent or null value, while
// nonnil day ranges and numeric pointers preserve explicit zero values.
type Schedule struct {
	// TimeZone is the optional IANA time-zone name.
	TimeZone *string `json:"time_zone,omitzero"`
	// Sun is the optional Sunday interval.
	Sun *DayRange `json:"sun,omitzero"`
	// Mon is the optional Monday interval.
	Mon *DayRange `json:"mon,omitzero"`
	// Tue is the optional Tuesday interval.
	Tue *DayRange `json:"tue,omitzero"`
	// Wed is the optional Wednesday interval.
	Wed *DayRange `json:"wed,omitzero"`
	// Thu is the optional Thursday interval.
	Thu *DayRange `json:"thu,omitzero"`
	// Fri is the optional Friday interval.
	Fri *DayRange `json:"fri,omitzero"`
	// Sat is the optional Saturday interval.
	Sat *DayRange `json:"sat,omitzero"`
}

// DayRange contains one daily blocking interval in milliseconds from midnight.
type DayRange struct {
	// Start is the optional interval start.
	Start *float64 `json:"start,omitzero"`
	// End is the optional interval end.
	End *float64 `json:"end,omitzero"`
}

// blockedServicesAllResponse preserves required response fields before conversion.
type blockedServicesAllResponse struct {
	// BlockedServices is nil when the required list is absent or null.
	BlockedServices *[]*blockedServiceResponse `json:"blocked_services"`
	// Groups is nil when the required list is absent or null.
	Groups *[]*serviceGroupResponse `json:"groups"`
}

// blockedServiceResponse preserves required and optional service fields.
type blockedServiceResponse struct {
	// IconSVG is nil when the required field is absent or null.
	IconSVG *string `json:"icon_svg"`
	// ID is nil when the required field is absent or null.
	ID *string `json:"id"`
	// Name is nil when the required field is absent or null.
	Name *string `json:"name"`
	// Rules is nil when the required list is absent or null.
	Rules *[]*string `json:"rules"`
	// GroupID is nil when the optional field is absent or null.
	GroupID *string `json:"group_id"`
}

// serviceGroupResponse preserves the required group identifier.
type serviceGroupResponse struct {
	// ID is nil when the required field is absent or null.
	ID *string `json:"id"`
}

// blockedServicesScheduleResponse preserves optional schedule fields.
type blockedServicesScheduleResponse struct {
	// Schedule is nil when the optional object is absent or null.
	Schedule *scheduleResponse `json:"schedule"`
	// IDs is nil when the optional list is absent or null.
	IDs *[]*string `json:"ids"`
}

// scheduleResponse preserves optional schedule fields.
type scheduleResponse struct {
	// TimeZone is nil when the optional field is absent or null.
	TimeZone *string `json:"time_zone"`
	// Sun is nil when the optional day is absent or null.
	Sun *dayRangeResponse `json:"sun"`
	// Mon is nil when the optional day is absent or null.
	Mon *dayRangeResponse `json:"mon"`
	// Tue is nil when the optional day is absent or null.
	Tue *dayRangeResponse `json:"tue"`
	// Wed is nil when the optional day is absent or null.
	Wed *dayRangeResponse `json:"wed"`
	// Thu is nil when the optional day is absent or null.
	Thu *dayRangeResponse `json:"thu"`
	// Fri is nil when the optional day is absent or null.
	Fri *dayRangeResponse `json:"fri"`
	// Sat is nil when the optional day is absent or null.
	Sat *dayRangeResponse `json:"sat"`
}

// dayRangeResponse preserves optional numeric schedule values.
type dayRangeResponse struct {
	// Start is nil when the optional value is absent or null.
	Start *float64 `json:"start"`
	// End is nil when the optional value is absent or null.
	End *float64 `json:"end"`
}

// blockedServicesScheduleRequest preserves optional update properties.
type blockedServicesScheduleRequest struct {
	// Schedule is nil when the optional object is omitted.
	Schedule *Schedule `json:"schedule,omitzero"`
	// IDs is nil when the optional list is omitted.
	IDs *[]string `json:"ids,omitzero"`
}

const (
	// BlockedServicesAllOperation identifies BlockedServicesAll errors.
	blockedServicesAllOperation = "blocked_services_all"
	// BlockedServicesScheduleOperation identifies BlockedServicesSchedule errors.
	blockedServicesScheduleOperation = "blocked_services_schedule"
	// BlockedServicesScheduleUpdateOperation identifies update errors.
	blockedServicesScheduleUpdateOperation = "blocked_services_schedule_update"
)

var (
	// ErrNullBlockedServicesAllResponse identifies a top-level null catalog.
	errNullBlockedServicesAllResponse = errors.New("blocked services all response must be a JSON object")
	// ErrRequiredBlockedServicesAllField identifies a missing required catalog field.
	errRequiredBlockedServicesAllField = errors.New("required blocked services all field is missing")
	// ErrRequiredBlockedServiceField identifies a missing required service field.
	errRequiredBlockedServiceField = errors.New("required blocked service field is missing")
	// ErrRequiredServiceGroupField identifies a missing required group field.
	errRequiredServiceGroupField = errors.New("required service group field is missing")
	// ErrRequiredBlockedServicesID identifies a null schedule identifier.
	errRequiredBlockedServicesID = errors.New("blocked services schedule identifier is null")
	// ErrNullBlockedServicesScheduleResponse identifies a top-level null schedule.
	errNullBlockedServicesScheduleResponse = errors.New(
		"blocked services schedule response must be a JSON object",
	)
	// ErrEncodeBlockedServicesSchedule identifies an update encoding failure.
	errEncodeBlockedServicesSchedule = errors.New("encode blocked services schedule")
)

var _ BlockedServicesService = (*Client)(nil)

// BlockedServicesAll retrieves the complete blocked-service catalog.
//
// The successful response must be a bounded JSON object containing both required
// arrays. Every catalog service must contain all required fields. Optional
// group identifiers preserve absent and null values as nil.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - catalog: The decoded blocked-service catalog when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, malformed JSON, or required-field failures; otherwise nil.
func (c *Client) BlockedServicesAll(ctx context.Context) (*BlockedServicesAll, error) {
	response, requestErr := c.get(ctx, blockedServicesAllOperation, "control/blocked_services/all")
	if requestErr != nil {
		return nil, requestErr
	}

	catalog, decodeErr := decodeBlockedServicesAll(response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return catalog, nil
}

// BlockedServicesSchedule retrieves the configured blocked-service schedule.
//
// The successful response must be a bounded JSON object. Both properties are
// optional; absent and null values decode to nil, while explicit empty and zero
// values are preserved.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - schedule: The decoded blocked-service schedule when the response is valid.
//   - err: An *Error for request, redirect, HTTP, response-limit, response-body,
//     media-type, or malformed JSON failures; otherwise nil.
func (c *Client) BlockedServicesSchedule(ctx context.Context) (*BlockedServicesSchedule, error) {
	response, requestErr := c.get(
		ctx,
		blockedServicesScheduleOperation,
		"control/blocked_services/get",
	)
	if requestErr != nil {
		return nil, requestErr
	}

	schedule, decodeErr := decodeBlockedServicesSchedule(response.body)
	if decodeErr != nil {
		return nil, decodeErr
	}

	return schedule, nil
}

// BlockedServicesScheduleUpdate updates the blocked-service schedule.
//
// The schedule is always sent as a JSON object. Nil properties are omitted;
// nonnil pointers preserve explicit empty objects, empty arrays, empty strings,
// and numeric zero values. Any 2xx response is accepted without interpreting
// its body, but the response is still bounded.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - schedule: The schedule and blocked-service identifiers to apply.
//
// Returns:
//   - err: An *Error for encoding, request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) BlockedServicesScheduleUpdate(
	ctx context.Context,
	schedule BlockedServicesSchedule,
) error {
	operation := blockedServicesScheduleUpdateOperation
	payload, err := json.Marshal(blockedServicesScheduleRequest(schedule))
	if err != nil {
		return blockedServicesJSONError(
			operation,
			http.MethodPut,
			fmt.Errorf("%w: %w", errEncodeBlockedServicesSchedule, err),
		)
	}

	requestErr := c.executeBlockedServicesUpdate(
		ctx,
		operation,
		"control/blocked_services/update",
		payload,
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// decodeBlockedServicesAll strictly decodes and validates a catalog response.
//
// Parameters:
//   - body: The bounded JSON response body.
//
// Returns:
//   - catalog: The validated domain catalog.
//   - err: A JSON-kind *Error for malformed JSON, null, or missing required
//     fields; otherwise nil.
func decodeBlockedServicesAll(body []byte) (*BlockedServicesAll, *Error) {
	var wireCatalog *blockedServicesAllResponse

	err := json.Unmarshal(body, &wireCatalog)
	if err != nil {
		return nil, blockedServicesJSONError(
			blockedServicesAllOperation,
			http.MethodGet,
			fmt.Errorf("decode response: %w", err),
		)
	}

	catalog, conversionErr := blockedServicesAllFromResponse(wireCatalog)
	if conversionErr != nil {
		return nil, blockedServicesJSONError(
			blockedServicesAllOperation,
			http.MethodGet,
			conversionErr,
		)
	}

	return catalog, nil
}

// blockedServicesAllFromResponse validates and converts a catalog response.
//
// Parameters:
//   - wireCatalog: The decoded catalog response, which may be nil for JSON null.
//
// Returns:
//   - catalog: The validated domain catalog.
//   - err: A top-level-null or missing-required-field error.
func blockedServicesAllFromResponse(
	wireCatalog *blockedServicesAllResponse,
) (*BlockedServicesAll, error) {
	if wireCatalog == nil {
		return nil, errNullBlockedServicesAllResponse
	}
	if wireCatalog.BlockedServices == nil || wireCatalog.Groups == nil {
		return nil, errRequiredBlockedServicesAllField
	}

	services, err := blockedServicesFromResponse(*wireCatalog.BlockedServices)
	if err != nil {
		return nil, fmt.Errorf("blocked_services: %w", err)
	}

	groups, err := serviceGroupsFromResponse(*wireCatalog.Groups)
	if err != nil {
		return nil, fmt.Errorf("groups: %w", err)
	}

	return &BlockedServicesAll{
		BlockedServices: services,
		Groups:          groups,
	}, nil
}

// blockedServicesFromResponse converts all catalog services.
//
// Parameters:
//   - wireServices: The decoded catalog service entries.
//
// Returns:
//   - services: The converted service entries.
//   - err: An error identifying a malformed or incomplete entry.
func blockedServicesFromResponse(
	wireServices []*blockedServiceResponse,
) ([]BlockedService, error) {
	services := make([]BlockedService, 0, len(wireServices))
	for index, wireService := range wireServices {
		service, err := blockedServiceFromResponse(wireService)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", index, err)
		}

		services = append(services, service)
	}

	return services, nil
}

// serviceGroupsFromResponse converts all service groups.
//
// Parameters:
//   - wireGroups: The decoded service-group entries.
//
// Returns:
//   - groups: The converted service-group entries.
//   - err: An error identifying a malformed or incomplete entry.
func serviceGroupsFromResponse(
	wireGroups []*serviceGroupResponse,
) ([]ServiceGroup, error) {
	groups := make([]ServiceGroup, 0, len(wireGroups))
	for index, wireGroup := range wireGroups {
		group, err := serviceGroupFromResponse(wireGroup)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", index, err)
		}

		groups = append(groups, group)
	}

	return groups, nil
}

// blockedServiceFromResponse converts one wire service into the domain model.
//
// Parameters:
//   - wireService: The decoded service response.
//
// Returns:
//   - service: The domain service when all required fields are present.
//   - err: An error identifying a missing required field.
func blockedServiceFromResponse(wireService *blockedServiceResponse) (BlockedService, error) {
	if wireService == nil ||
		wireService.IconSVG == nil ||
		wireService.ID == nil ||
		wireService.Name == nil ||
		wireService.Rules == nil {
		return BlockedService{}, errRequiredBlockedServiceField
	}

	rules := make([]string, 0, len(*wireService.Rules))
	for index, rule := range *wireService.Rules {
		if rule == nil {
			return BlockedService{}, fmt.Errorf("rules[%d]: %w", index, errRequiredBlockedServiceField)
		}

		rules = append(rules, *rule)
	}

	return BlockedService{
		IconSVG: *wireService.IconSVG,
		ID:      *wireService.ID,
		Name:    *wireService.Name,
		Rules:   rules,
		GroupID: wireService.GroupID,
	}, nil
}

// serviceGroupFromResponse converts one wire group into the domain model.
//
// Parameters:
//   - wireGroup: The decoded service-group response.
//
// Returns:
//   - group: The domain group when its identifier is present.
//   - err: An error identifying a missing identifier.
func serviceGroupFromResponse(wireGroup *serviceGroupResponse) (ServiceGroup, error) {
	if wireGroup == nil || wireGroup.ID == nil {
		return ServiceGroup{}, errRequiredServiceGroupField
	}

	return ServiceGroup{ID: *wireGroup.ID}, nil
}

// decodeBlockedServicesSchedule strictly decodes a schedule response.
//
// Parameters:
//   - body: The bounded JSON response body.
//
// Returns:
//   - schedule: The decoded domain schedule.
//   - err: A JSON-kind *Error for malformed JSON or a top-level null object.
func decodeBlockedServicesSchedule(body []byte) (*BlockedServicesSchedule, *Error) {
	var wireSchedule *blockedServicesScheduleResponse

	err := json.Unmarshal(body, &wireSchedule)
	if err != nil {
		return nil, blockedServicesJSONError(
			blockedServicesScheduleOperation,
			http.MethodGet,
			fmt.Errorf("decode response: %w", err),
		)
	}
	if wireSchedule == nil {
		return nil, blockedServicesJSONError(
			blockedServicesScheduleOperation,
			http.MethodGet,
			errNullBlockedServicesScheduleResponse,
		)
	}

	var ids *[]string

	if wireSchedule.IDs != nil {
		ids, err = blockedServicesIDsFromResponse(wireSchedule.IDs)
		if err != nil {
			return nil, blockedServicesJSONError(
				blockedServicesScheduleOperation,
				http.MethodGet,
				err,
			)
		}
	}

	return &BlockedServicesSchedule{
		Schedule: scheduleFromResponse(wireSchedule.Schedule),
		IDs:      ids,
	}, nil
}

// blockedServicesIDsFromResponse converts a present optional identifier list.
//
// Parameters:
//   - wireIDs: The decoded identifier list. The caller guarantees it is non-nil
//     so an absent or null list is handled by its own nil check.
//
// Returns:
//   - ids: A pointer to the converted list, which is empty when the decoded
//     list is empty.
//   - err: An error identifying a null list member.
func blockedServicesIDsFromResponse(wireIDs *[]*string) (*[]string, error) {
	ids := make([]string, 0, len(*wireIDs))
	for index, id := range *wireIDs {
		if id == nil {
			return nil, fmt.Errorf("ids[%d]: %w", index, errRequiredBlockedServicesID)
		}

		ids = append(ids, *id)
	}

	return &ids, nil
}

// scheduleFromResponse converts a wire schedule into the domain model.
//
// Parameters:
//   - wireSchedule: The decoded schedule response.
//
// Returns:
//   - schedule: The domain schedule, or nil when the object was absent or null.
func scheduleFromResponse(wireSchedule *scheduleResponse) *Schedule {
	if wireSchedule == nil {
		return nil
	}

	return &Schedule{
		TimeZone: wireSchedule.TimeZone,
		Sun:      dayRangeFromResponse(wireSchedule.Sun),
		Mon:      dayRangeFromResponse(wireSchedule.Mon),
		Tue:      dayRangeFromResponse(wireSchedule.Tue),
		Wed:      dayRangeFromResponse(wireSchedule.Wed),
		Thu:      dayRangeFromResponse(wireSchedule.Thu),
		Fri:      dayRangeFromResponse(wireSchedule.Fri),
		Sat:      dayRangeFromResponse(wireSchedule.Sat),
	}
}

// dayRangeFromResponse converts a wire day range into the domain model.
//
// Parameters:
//   - wireRange: The decoded day-range response.
//
// Returns:
//   - dayRange: The domain range, or nil when the object was absent or null.
func dayRangeFromResponse(wireRange *dayRangeResponse) *DayRange {
	if wireRange == nil {
		return nil
	}

	return &DayRange{
		Start: wireRange.Start,
		End:   wireRange.End,
	}
}

// executeBlockedServicesUpdate sends an encoded schedule and consumes its
// bounded, body-agnostic success response.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//   - operation: The operation identifier placed on structured errors.
//   - endpoint: The control endpoint relative to the client's API base URL.
//   - payload: The encoded JSON request body.
//
// Returns:
//   - err: An *Error for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) executeBlockedServicesUpdate(
	ctx context.Context,
	operation string,
	endpoint string,
	payload []byte,
) *Error {
	requestContext, cancel := context.WithTimeout(ctx, c.requestTimeout)

	request, requestErr := c.newGlobalRequest(
		requestContext,
		operation,
		http.MethodPut,
		endpoint,
		bytes.NewReader(payload),
	)
	if requestErr != nil {
		cancel()

		return requestErr
	}

	response, requestErr := c.executeRequest(requestContext, operation, request)
	if requestErr != nil {
		requestErr.Method = http.MethodPut

		cancel()

		return requestErr
	}

	_, responseErr := readGlobalResponse(
		operation,
		http.MethodPut,
		response,
		c.maxResponseBytes,
	)

	cancel()

	return responseErr
}

// blockedServicesJSONError creates a structured blocked-services JSON error.
//
// Parameters:
//   - operation: The operation identifier placed on the error.
//   - method: The HTTP method placed on the error.
//   - cause: The decoding, validation, or encoding cause.
//
// Returns:
//   - The structured JSON client error.
func blockedServicesJSONError(operation, method string, cause error) *Error {
	clientErr := newError(ErrorKindJSON)

	clientErr.Operation = operation
	clientErr.Method = method
	clientErr.Err = cause

	return clientErr
}
