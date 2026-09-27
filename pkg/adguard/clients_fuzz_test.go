// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// clientsFuzzTransport rejects every request before it can reach a socket.
type clientsFuzzTransport struct{}

// clientsFuzzMaxInputBytes bounds string and collection work per fuzz input.
const clientsFuzzMaxInputBytes = 16 << 10

// clientsFuzzMaxCollectionItems bounds duplicate and overlap validation work.
const clientsFuzzMaxCollectionItems = 2

// FuzzClientsResponses exercises configured-client, search, and access-list
// response decoding with bounded structured failures.
func FuzzClientsResponses(fuzz *testing.F) {
	fuzz.Add(uint8(0), []byte(`{}`))
	fuzz.Add(uint8(0), []byte(`{"clients":null,"auto_clients":null,"supported_tags":null}`))
	fuzz.Add(uint8(0), []byte(`{"clients":[],"auto_clients":[],"supported_tags":[]}`))
	fuzz.Add(uint8(0), []byte(
		`{"clients":[{"name":"desk","ids":["192.0.2.1"],"filtering_enabled":false}],`+
			`"auto_clients":[{"ip":"192.0.2.2","whois_info":{}}],`+
			`"supported_tags":["trusted"]}`,
	))
	fuzz.Add(uint8(1), []byte(`[]`))
	fuzz.Add(uint8(1), []byte(`[{}]`))
	fuzz.Add(uint8(1), []byte(`[null]`))
	fuzz.Add(uint8(1), []byte(`[{"192.0.2.1":{"name":"","ids":[],"filtering_enabled":false,"whois_info":{}}}]`))
	fuzz.Add(uint8(2), []byte(`{}`))
	fuzz.Add(uint8(2), []byte(`{"allowed_clients":null,"disallowed_clients":null,"blocked_hosts":null}`))
	fuzz.Add(uint8(2), []byte(`{"allowed_clients":[],"disallowed_clients":[],"blocked_hosts":[]}`))
	fuzz.Add(uint8(2), []byte(
		`{"allowed_clients":["192.0.2.1"],"disallowed_clients":[],`+
			`"blocked_hosts":["ads.example"]}`,
	))
	fuzz.Add(uint8(0), []byte(`null`))
	fuzz.Add(uint8(1), []byte(`{"clients":`))

	fuzz.Fuzz(func(t *testing.T, responseType uint8, body []byte) {
		if len(body) > clientsFuzzMaxInputBytes {
			return
		}

		exerciseClientsFuzzResponse(t, responseType, body)
	})
}

// FuzzClientAccessRequests exercises client and access validation, JSON
// presence semantics, and request errors without network access.
func FuzzClientAccessRequests(fuzz *testing.F) {
	fuzz.Add("desk", "192.0.2.1", "one", "two", true, uint8(0))
	fuzz.Add("", "", "", "", false, uint8(0))
	fuzz.Add("", "", "", "", false, uint8(1))
	fuzz.Add(" ", "client-42", "", "one", false, uint8(1))
	fuzz.Add("desk", "one", "same", "same", false, uint8(2))
	fuzz.Add("desk", "one", "one", "two", true, uint8(3))

	fuzz.Fuzz(func(
		t *testing.T,
		name string,
		identifier string,
		first string,
		second string,
		enabled bool,
		selector uint8,
	) {
		if !clientsFuzzInputBounded(t, name, identifier, first, second) {
			return
		}

		client := newClientsFuzzClient(t)
		values := clientsFuzzValues(selector, first, second)
		config := newClientsFuzzConfig(name, values, enabled)
		updateData := ClientUpdateData{}
		if selector%2 != 0 {
			configuredSearch := newClientsFuzzSafeSearch(enabled)

			config.SafeSearch = &configuredSearch
			config.BlockedServicesSchedule = map[string]any{"identifier": identifier}
			updateData = newClientsFuzzUpdateData(name, identifier, values, enabled)
		}

		exerciseClientsFuzzConfig(t, client, name, config, enabled)
		exerciseClientsFuzzUpdate(t, client, name, updateData)
		exerciseClientsFuzzAccess(t, client, identifier, values, selector)
		exerciseClientsFuzzSearch(t, client, identifier)
	})
}

// RoundTrip prevents client fuzz requests from reaching an external service.
//
// Parameters:
//   - request: The request rejected by the transport.
//
// Returns:
//   - nil: No response is produced.
//   - [context.Canceled]: The deterministic transport failure.
func (clientsFuzzTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, context.Canceled
}

// newClientsFuzzClient creates a client whose transport cannot leave the test
// process.
//
// Parameters:
//   - tb: The fuzz or test context receiving configuration failures.
//
// Returns:
//   - client: The offline clients client.
func newClientsFuzzClient(tb testing.TB) *Client {
	tb.Helper()

	client, err := NewClient(
		localTestServerURL,
		WithHTTPClient(&http.Client{Transport: clientsFuzzTransport{}}),
	)
	if err != nil {
		tb.Fatalf("create clients fuzz client: %v", err)
	}

	return client
}

// clientsFuzzInputBounded reports whether all client request strings are valid
// UTF-8 and remain within the per-input work budget.
//
// Parameters:
//   - tb: The fuzz context receiving bound checks.
//   - name: The fuzzed client name.
//   - identifier: The fuzzed client identifier.
//   - first: The first fuzzed collection value.
//   - second: The second fuzzed collection value.
//
// Returns:
//   - bounded: Whether the input can be exercised safely.
func clientsFuzzInputBounded(
	tb testing.TB,
	name string,
	identifier string,
	first string,
	second string,
) bool {
	tb.Helper()

	totalBytes := len(name) + len(identifier) + len(first) + len(second)
	maxStringBytes := clientsFuzzMaxInputBytes / clientsFuzzMaxCollectionItems

	return totalBytes <= clientsFuzzMaxInputBytes &&
		utf8.ValidString(name) &&
		utf8.ValidString(identifier) &&
		utf8.ValidString(first) &&
		utf8.ValidString(second) &&
		len(name) <= maxStringBytes &&
		len(identifier) <= maxStringBytes &&
		len(first) <= maxStringBytes &&
		len(second) <= maxStringBytes
}

// clientsFuzzValues creates nil, empty, or bounded duplicate-capable collections.
//
// Parameters:
//   - selector: The collection-shape selector supplied by the fuzzer.
//   - first: The first collection value.
//   - second: The second collection value.
//
// Returns:
//   - values: The selected request collection.
func clientsFuzzValues(selector uint8, first, second string) []string {
	switch selector % 3 {
	case 0:
		return nil
	case 1:
		return []string{}
	case 2:
		return []string{first, second}
	default:
		return []string{first}
	}
}

// newClientsFuzzSafeSearch creates a fully present safe-search request model.
//
// Parameters:
//   - enabled: The value assigned to every provider pointer.
//
// Returns:
//   - safeSearch: The safe-search model.
func newClientsFuzzSafeSearch(enabled bool) SafeSearchConfig {
	return SafeSearchConfig{
		Enabled:    new(enabled),
		Bing:       new(enabled),
		DuckDuckGo: new(enabled),
		Ecosia:     new(enabled),
		Google:     new(enabled),
		Pixabay:    new(enabled),
		Yandex:     new(enabled),
		YouTube:    new(enabled),
	}
}

// newClientsFuzzConfig creates a fully specified add-client request model.
//
// Parameters:
//   - name: The client name.
//   - values: The client identifiers and optional collections.
//   - enabled: The value assigned to every ordinary boolean field.
//
// Returns:
//   - config: The add-client model without nested presence-sensitive fields.
func newClientsFuzzConfig(name string, values []string, enabled bool) ClientConfig {
	return ClientConfig{
		Name:                     name,
		IDs:                      values,
		UseGlobalSettings:        enabled,
		FilteringEnabled:         enabled,
		ParentalEnabled:          enabled,
		SafebrowsingEnabled:      enabled,
		SafesearchEnabled:        enabled,
		SafeSearch:               nil,
		UseGlobalBlockedServices: enabled,
		BlockedServicesSchedule:  nil,
		BlockedServices:          values,
		Upstreams:                values,
		Tags:                     values,
		IgnoreQuerylog:           enabled,
		IgnoreStatistics:         enabled,
		UpstreamsCacheEnabled:    enabled,
		UpstreamsCacheSize:       int64(len(values)),
	}
}

// newClientsFuzzUpdateData creates a fully specified presence-sensitive update.
//
// Parameters:
//   - name: The optional replacement name.
//   - identifier: A value used by the optional schedule object.
//   - values: The optional replacement collections.
//   - enabled: The value assigned to every optional boolean.
//
// Returns:
//   - data: The update patch model.
func newClientsFuzzUpdateData(
	name string,
	identifier string,
	values []string,
	enabled bool,
) ClientUpdateData {
	configuredSearch := newClientsFuzzSafeSearch(enabled)
	schedule := map[string]any{"identifier": identifier}
	cacheSize := int64(len(values))

	return ClientUpdateData{
		Name:                     new(name),
		IDs:                      new(values),
		UseGlobalSettings:        new(enabled),
		FilteringEnabled:         new(enabled),
		ParentalEnabled:          new(enabled),
		SafebrowsingEnabled:      new(enabled),
		SafesearchEnabled:        new(enabled),
		SafeSearch:               &configuredSearch,
		UseGlobalBlockedServices: new(enabled),
		BlockedServicesSchedule:  new(schedule),
		BlockedServices:          new(values),
		Upstreams:                new(values),
		Tags:                     new(values),
		IgnoreQuerylog:           new(enabled),
		IgnoreStatistics:         new(enabled),
		UpstreamsCacheEnabled:    new(enabled),
		UpstreamsCacheSize:       new(cacheSize),
	}
}

// exerciseClientsFuzzConfig validates and sends one add-client request, then
// checks request presence and structured failure metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - client: The offline clients client.
//   - name: The client name.
//   - config: The add-client model under test.
//   - enabled: The value assigned to every ordinary boolean field.
func exerciseClientsFuzzConfig(
	tb testing.TB,
	client *Client,
	name string,
	config ClientConfig,
	enabled bool,
) {
	tb.Helper()

	safeSearchPresent := config.SafeSearch != nil
	schedulePresent := config.BlockedServicesSchedule != nil
	validationErr := validateClientConfig(config)
	err := client.ClientsAdd(tb.Context(), config)
	if validationErr == nil {
		requireClientsFuzzError(tb, err, ErrorKindRequest, "clients_add", http.MethodPost)

		if !errors.Is(err, context.Canceled) {
			tb.Fatalf("clients add error does not preserve the transport cause: %v", err)
		}
	} else {
		requireClientsFuzzError(tb, err, ErrorKindConfig, "clients_add", http.MethodPost)

		if !errors.Is(err, validationErr) {
			tb.Fatalf("clients add error does not preserve validation cause: %v", err)
		}
	}

	request := newClientConfigRequest(config)
	assertClientsFuzzJSONFields(tb, request, map[string]bool{
		"name":                        name != "",
		"ids":                         len(config.IDs) != 0,
		"use_global_settings":         enabled,
		"filtering_enabled":           enabled,
		"parental_enabled":            enabled,
		"safebrowsing_enabled":        enabled,
		"safesearch_enabled":          enabled,
		"safe_search":                 safeSearchPresent,
		"use_global_blocked_services": enabled,
		"blocked_services_schedule":   schedulePresent,
		"blocked_services":            len(config.BlockedServices) != 0,
		"upstreams":                   len(config.Upstreams) != 0,
		"tags":                        len(config.Tags) != 0,
		"ignore_querylog":             enabled,
		"ignore_statistics":           enabled,
		"upstreams_cache_enabled":     enabled,
		"upstreams_cache_size":        config.UpstreamsCacheSize != 0,
	})

	if safeSearchPresent {
		assertClientsFuzzJSONFields(tb, config.SafeSearch, map[string]bool{
			"enabled":    true,
			"bing":       true,
			"duckduckgo": true,
			"ecosia":     true,
			"google":     true,
			"pixabay":    true,
			"yandex":     true,
			"youtube":    true,
		})
	}
}

// exerciseClientsFuzzUpdate validates and sends one presence-sensitive update,
// then checks every optional field and its structured failure metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - client: The offline clients client.
//   - name: The target client name.
//   - data: The optional update patch model.
func exerciseClientsFuzzUpdate(
	tb testing.TB,
	client *Client,
	name string,
	data ClientUpdateData,
) {
	tb.Helper()

	request := ClientUpdate{
		Name: name,
		Data: &data,
	}
	err := client.ClientsUpdate(tb.Context(), request)
	if strings.TrimSpace(name) == "" {
		requireClientsFuzzError(tb, err, ErrorKindConfig, "clients_update", http.MethodPost)

		if !errors.Is(err, errClientNameRequired) {
			tb.Fatalf("clients update error does not preserve name validation: %v", err)
		}
	} else {
		requireClientsFuzzError(tb, err, ErrorKindRequest, "clients_update", http.MethodPost)

		if !errors.Is(err, context.Canceled) {
			tb.Fatalf("clients update error does not preserve the transport cause: %v", err)
		}
	}

	assertClientsFuzzJSONFields(tb, request, map[string]bool{
		"name": name != "",
		"data": true,
	})
	assertClientsFuzzJSONFields(tb, data, map[string]bool{
		"name":                        data.Name != nil,
		"ids":                         data.IDs != nil,
		"use_global_settings":         data.UseGlobalSettings != nil,
		"filtering_enabled":           data.FilteringEnabled != nil,
		"parental_enabled":            data.ParentalEnabled != nil,
		"safebrowsing_enabled":        data.SafebrowsingEnabled != nil,
		"safesearch_enabled":          data.SafesearchEnabled != nil,
		"safe_search":                 data.SafeSearch != nil,
		"use_global_blocked_services": data.UseGlobalBlockedServices != nil,
		"blocked_services_schedule":   data.BlockedServicesSchedule != nil,
		"blocked_services":            data.BlockedServices != nil,
		"upstreams":                   data.Upstreams != nil,
		"tags":                        data.Tags != nil,
		"ignore_querylog":             data.IgnoreQuerylog != nil,
		"ignore_statistics":           data.IgnoreStatistics != nil,
		"upstreams_cache_enabled":     data.UpstreamsCacheEnabled != nil,
		"upstreams_cache_size":        data.UpstreamsCacheSize != nil,
	})
}

// exerciseClientsFuzzAccess exercises duplicate and overlap validation, request
// serialization, and structured config or transport errors.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - client: The offline clients client.
//   - identifier: A value used to form a distinct or overlapping identifier.
//   - values: The allowed-client and blocked-host values.
//   - selector: The access-list shape selector.
func exerciseClientsFuzzAccess(
	tb testing.TB,
	client *Client,
	identifier string,
	values []string,
	selector uint8,
) {
	tb.Helper()

	disallowed := clientsFuzzDisallowedClients(selector, identifier, values)
	access := AccessList{
		AllowedClients:    values,
		DisallowedClients: disallowed,
		BlockedHosts:      values,
	}
	validationErr := validateAccessList(access)
	err := client.AccessSet(tb.Context(), access)
	if validationErr == nil {
		requireClientsFuzzError(tb, err, ErrorKindRequest, "access_set", http.MethodPost)

		if !errors.Is(err, context.Canceled) {
			tb.Fatalf("access set error does not preserve the transport cause: %v", err)
		}
	} else {
		requireClientsFuzzError(tb, err, ErrorKindConfig, "access_set", http.MethodPost)

		if !errors.Is(err, validationErr) {
			tb.Fatalf("access set error does not preserve validation cause: %v", err)
		}
	}

	assertClientsFuzzJSONFields(tb, access, map[string]bool{
		"allowed_clients":    len(access.AllowedClients) != 0,
		"disallowed_clients": len(access.DisallowedClients) != 0,
		"blocked_hosts":      len(access.BlockedHosts) != 0,
	})
}

// clientsFuzzDisallowedClients creates absent, distinct, or overlapping values.
//
// Parameters:
//   - selector: The access-list shape selector supplied by the fuzzer.
//   - identifier: The value used for distinct or overlapping identifiers.
//   - values: The allowed-client and blocked-host values.
//
// Returns:
//   - disallowed: The selected disallowed-client list.
func clientsFuzzDisallowedClients(
	selector uint8,
	identifier string,
	values []string,
) []string {
	switch selector % 3 {
	case 0:
		return nil
	case 1:
		return []string{identifier + "-disallowed"}
	case 2:
		if len(values) == 0 {
			return []string{identifier}
		}

		return values[:1]
	default:
		return []string{identifier}
	}
}

// exerciseClientsFuzzSearch sends one exact-match search and checks request
// presence and structured config or transport errors.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - client: The offline clients client.
//   - identifier: The search identifier.
func exerciseClientsFuzzSearch(tb testing.TB, client *Client, identifier string) {
	tb.Helper()

	request := ClientsSearchRequest{
		Clients: []ClientsSearchRequestItem{{ID: identifier}},
	}
	_, err := client.ClientsSearch(tb.Context(), request)
	if strings.TrimSpace(identifier) == "" {
		requireClientsFuzzError(tb, err, ErrorKindConfig, "clients_search", http.MethodPost)

		if !errors.Is(err, errClientSearchIDRequired) {
			tb.Fatalf("clients search error does not preserve identifier validation: %v", err)
		}
	} else {
		requireClientsFuzzError(tb, err, ErrorKindRequest, "clients_search", http.MethodPost)

		if !errors.Is(err, context.Canceled) {
			tb.Fatalf("clients search error does not preserve the transport cause: %v", err)
		}
	}

	assertClientsFuzzJSONFields(tb, request, map[string]bool{"clients": true})
}

// exerciseClientsFuzzResponse validates and decodes one client response model
// and checks its result or structured JSON error.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - responseType: The response-model selector supplied by the fuzzer.
//   - body: The bounded JSON response body.
func exerciseClientsFuzzResponse(tb testing.TB, responseType uint8, body []byte) {
	tb.Helper()

	var (
		operation string
		method    string
	)

	switch responseType % 3 {
	case 0:
		operation = "clients_status"
		method = http.MethodGet
	case 1:
		operation = "clients_search"
		method = http.MethodPost
	case 2:
		operation = "access_list"
		method = http.MethodGet
	default:
		tb.Fatalf("unreachable clients response selector %d", responseType%3)
	}

	response := &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     make(http.Header),
	}
	response.Header.Set("Content-Type", jsonContentType)

	decodedBody, responseErr := validateClientsResponse(
		operation,
		method,
		response,
		body,
		clientsResponseJSON,
	)
	if responseErr != nil {
		requireClientsFuzzError(tb, responseErr, ErrorKindJSON, operation, method)

		return
	}

	decodeErr := decodeClientsFuzzResponse(tb, responseType, decodedBody, operation, method)
	if decodeErr != nil {
		requireClientsFuzzError(tb, decodeErr, ErrorKindJSON, operation, method)
	}
}

// decodeClientsFuzzResponse decodes one validated client response model and
// wraps JSON failures with the public client error contract.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - responseType: The response-model selector supplied by the fuzzer.
//   - body: The validated JSON response body.
//   - operation: The operation name attached to decode errors.
//   - method: The HTTP method attached to decode errors.
//
// Returns:
//   - err: A structured JSON decoding error, or nil after a valid decode.
func decodeClientsFuzzResponse(
	tb testing.TB,
	responseType uint8,
	body []byte,
	operation string,
	method string,
) error {
	tb.Helper()

	var err error

	switch responseType % 3 {
	case 0:
		result := &ClientsStatus{}

		err = json.Unmarshal(body, result)
	case 1:
		var result []ClientFindEntry

		err = json.Unmarshal(body, &result)
		if err == nil && result == nil {
			tb.Fatal("clients search returned a nil slice for a successful array response")
		}
	case 2:
		result := &AccessList{}

		err = json.Unmarshal(body, result)
	default:
		tb.Fatalf("unreachable clients response selector %d", responseType%3)
	}
	if err != nil {
		return clientJSONError(
			operation,
			method,
			fmt.Errorf("%w: %w", errClientJSONResponse, err),
		)
	}

	return nil
}

// assertClientsFuzzJSONFields checks the exact key presence of one encoded
// client or access request model.
//
// Parameters:
//   - tb: The fuzz context receiving JSON failures.
//   - value: The request model to encode.
//   - expected: Whether each possible JSON key must be present.
func assertClientsFuzzJSONFields(tb testing.TB, value any, expected map[string]bool) {
	tb.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		tb.Fatalf("encode clients request model: %v", err)
	}

	var fields map[string]any

	err = json.Unmarshal(encoded, &fields)
	if err != nil {
		tb.Fatalf("decode clients request JSON: %v", err)
	}

	assertClientsFuzzJSONPresence(tb, fields, expected, encoded)
}

// assertClientsFuzzJSONPresence checks one decoded object's exact key set.
//
// Parameters:
//   - tb: The fuzz context receiving JSON failures.
//   - fields: The decoded request object.
//   - expected: Whether each possible JSON key must be present.
//   - encoded: The original JSON used for failure context.
func assertClientsFuzzJSONPresence(
	tb testing.TB,
	fields map[string]any,
	expected map[string]bool,
	encoded []byte,
) {
	tb.Helper()

	expectedCount := 0

	for key, mustBePresent := range expected {
		if mustBePresent {
			expectedCount++
		}

		_, present := fields[key]
		if present != mustBePresent {
			tb.Fatalf("clients request key %q presence = %t, want %t", key, present, mustBePresent)
		}
	}
	if len(fields) != expectedCount {
		tb.Fatalf("clients request has %d keys, want %d: %s", len(fields), expectedCount, encoded)
	}
}

// requireClientsFuzzError verifies that a clients error has the required
// structured classification and metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - err: The error to inspect.
//   - kind: The expected structured error kind.
//   - operation: The expected operation name.
//   - method: The expected HTTP method.
func requireClientsFuzzError(
	tb testing.TB,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) {
	tb.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	if !ok || clientErr == nil {
		tb.Fatalf("clients error is not structured: %T %v", err, err)
	}
	if clientErr.Kind != kind || clientErr.Operation != operation || clientErr.Method != method {
		tb.Fatalf(
			"clients error metadata = (%q, %q, %q), want (%q, %q, %q)",
			clientErr.Kind,
			clientErr.Operation,
			clientErr.Method,
			kind,
			operation,
			method,
		)
	}
	if clientErr.Err == nil {
		tb.Fatalf("structured clients error %q has no cause", operation)
	}
}
