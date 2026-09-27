// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/v2"
	"errors"
	"net/http"
	"testing"
)

// filteringFuzzRequestModels contains the request models decoded from one fuzz
// input so their presence semantics can be checked together.
type filteringFuzzRequestModels struct {
	// config contains the general filtering configuration.
	config FilteringConfig
	// add contains the add-subscription request.
	add AddFilteringURLRequest
	// remove contains the remove-subscription request.
	remove RemoveFilteringURLRequest
	// refresh contains the refresh request.
	refresh RefreshFilteringRequest
	// rules contains the replacement-rules request.
	rules SetFilteringRulesRequest
}

// filteringFuzzTransport rejects every request before it can reach a socket.
type filteringFuzzTransport struct{}

// filteringFuzzMaxInputBytes bounds JSON parsing and allocation per fuzz input.
const filteringFuzzMaxInputBytes = 16 << 10

// FuzzFilteringResponses exercises filtering status, host-check, and refresh
// response decoding with bounded structured failures.
func FuzzFilteringResponses(fuzz *testing.F) {
	fuzz.Add(uint8(0), []byte(`{}`))
	fuzz.Add(uint8(0), []byte(
		`{"enabled":null,"interval":null,"filters":null,`+
			`"whitelist_filters":null,"user_rules":null}`,
	))
	fuzz.Add(uint8(0), []byte(`{"enabled":false,"interval":0,"filters":[],"whitelist_filters":[],"user_rules":[]}`))
	fuzz.Add(uint8(0), []byte(
		`{"filters":[{"enabled":true,"id":1,"name":"Example","rules_count":2,`+
			`"url":"https://example.test/list.txt","last_updated":"2026-01-02T03:04:05Z"}]}`,
	))
	fuzz.Add(uint8(0), []byte(`{"filters":[{"id":1}]}`))
	fuzz.Add(uint8(1), []byte(`{}`))
	fuzz.Add(uint8(1), []byte(
		`{"reason":null,"filter_id":null,"rule":null,"rules":null,`+
			`"service_name":null,"cname":null,"ip_addrs":null}`,
	))
	fuzz.Add(uint8(1), []byte(
		`{"reason":"NotFilteredNotFound","filter_id":0,"rule":"","rules":[],`+
			`"service_name":"","cname":"","ip_addrs":[]}`,
	))
	fuzz.Add(uint8(1), []byte(`{"reason":"unknown"}`))
	fuzz.Add(uint8(2), []byte(`{}`))
	fuzz.Add(uint8(2), []byte(`{"updated":null}`))
	fuzz.Add(uint8(2), []byte(`{"updated":0}`))
	fuzz.Add(uint8(2), []byte(`null`))
	fuzz.Add(uint8(2), []byte(`{"updated":`))

	fuzz.Fuzz(func(t *testing.T, responseType uint8, body []byte) {
		if len(body) > filteringFuzzMaxInputBytes {
			return
		}

		exerciseFilteringFuzzResponse(t, responseType, body)
	})
}

// FuzzFilteringRequestModels exercises filtering request JSON presence,
// emptiness, false, and null handling without network access.
func FuzzFilteringRequestModels(fuzz *testing.F) {
	fuzz.Add([]byte(`{}`))
	fuzz.Add([]byte(`{"enabled":null,"interval":null,"name":null,"url":null,"whitelist":null,"rules":null}`))
	fuzz.Add([]byte(`{"enabled":false,"interval":0,"name":"","url":"","whitelist":false,"rules":[]}`))
	fuzz.Add([]byte(
		`{"enabled":true,"interval":24,"name":"Example",` +
			`"url":"https://example.test/list.txt","whitelist":true,` +
			`"rules":["||example.org^"]}`,
	))
	fuzz.Add([]byte(`[]`))
	fuzz.Add([]byte(`{"enabled":`))

	fuzz.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > filteringFuzzMaxInputBytes {
			return
		}

		models, ok := decodeFilteringFuzzRequests(body)
		if !ok {
			return
		}

		assertFilteringFuzzRequestJSON(t, models)
		exerciseFilteringFuzzMutations(t, models)
	})
}

// RoundTrip prevents filtering fuzz mutations from reaching an external service.
//
// Parameters:
//   - request: The request rejected by the transport.
//
// Returns:
//   - nil: No response is produced.
//   - [context.Canceled]: The deterministic transport failure.
func (filteringFuzzTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, context.Canceled
}

// newFilteringFuzzClient creates a client whose transport cannot leave the test
// process.
//
// Parameters:
//   - tb: The fuzz or test context receiving configuration failures.
//
// Returns:
//   - client: The offline filtering client.
func newFilteringFuzzClient(tb testing.TB) *Client {
	tb.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(&http.Client{Transport: filteringFuzzTransport{}}),
	)
	if err != nil {
		tb.Fatalf("create filtering fuzz client: %v", err)
	}

	return client
}

// decodeFilteringFuzzRequests decodes one JSON object into every filtering
// request model that shares its optional fields.
//
// Parameters:
//   - body: The bounded fuzz input.
//
// Returns:
//   - models: The decoded request models.
//   - ok: Whether every model accepted the input.
func decodeFilteringFuzzRequests(body []byte) (filteringFuzzRequestModels, bool) {
	var models filteringFuzzRequestModels

	targets := []any{
		&models.config,
		&models.add,
		&models.remove,
		&models.refresh,
		&models.rules,
	}
	for _, target := range targets {
		err := json.Unmarshal(body, target)
		if err != nil {
			return filteringFuzzRequestModels{}, false
		}
	}

	return models, true
}

// exerciseFilteringFuzzResponse dispatches one bounded filtering response to
// its model-specific invariant checks.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - responseType: The response-model selector supplied by the fuzzer.
//   - body: The bounded JSON response body.
func exerciseFilteringFuzzResponse(tb testing.TB, responseType uint8, body []byte) {
	tb.Helper()

	switch responseType % 3 {
	case 0:
		exerciseFilteringStatusFuzzResponse(tb, body)
	case 1:
		exerciseFilteredHostFuzzResponse(tb, body)
	case 2:
		exerciseFilteringRefreshFuzzResponse(tb, body)
	default:
		tb.Fatalf("unreachable filtering response selector %d", responseType%3)
	}
}

// exerciseFilteringStatusFuzzResponse checks status decoding and error metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - body: The bounded JSON response body.
func exerciseFilteringStatusFuzzResponse(tb testing.TB, body []byte) {
	tb.Helper()

	result, err := decodeFilteringStatus(body)
	if err != nil {
		if result != nil {
			tb.Fatal("filtering status returned a result with a JSON error")
		}

		requireFilteringFuzzError(tb, err, ErrorKindJSON, filteringStatusOperation, http.MethodGet)

		return
	}
	if result == nil {
		tb.Fatal("filtering status returned a nil result without an error")
	}
}

// exerciseFilteredHostFuzzResponse checks host decoding and reason validation.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - body: The bounded JSON response body.
func exerciseFilteredHostFuzzResponse(tb testing.TB, body []byte) {
	tb.Helper()

	result, err := decodeFilteredHostResult(body)
	if err != nil {
		if result != nil {
			tb.Fatal("filtered host returned a result with a JSON error")
		}

		requireFilteringFuzzError(tb, err, ErrorKindJSON, filteringCheckHostOperation, http.MethodGet)

		return
	}
	if result == nil {
		tb.Fatal("filtered host returned a nil result without an error")
	}
	if result.Reason != nil && !validFilteringReason(*result.Reason) {
		tb.Fatalf("filtered host accepted invalid reason %q", *result.Reason)
	}
}

// exerciseFilteringRefreshFuzzResponse checks refresh decoding and error metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - body: The bounded JSON response body.
func exerciseFilteringRefreshFuzzResponse(tb testing.TB, body []byte) {
	tb.Helper()

	result, err := unmarshalFilteringRefreshResponse(body)
	if err != nil {
		if result != nil {
			tb.Fatal("filtering refresh returned a result with a JSON error")
		}

		requireFilteringFuzzError(tb, err, ErrorKindJSON, filteringRefreshOperation, http.MethodPost)

		return
	}
	if result == nil {
		tb.Fatal("filtering refresh returned a nil result without an error")
	}
}

// unmarshalFilteringRefreshResponse decodes a refresh response with the same
// object and structured-error policy used by RefreshFiltering.
//
// Parameters:
//   - body: The bounded JSON response body.
//
// Returns:
//   - result: The decoded refresh response when valid.
//   - err: A structured JSON error otherwise.
func unmarshalFilteringRefreshResponse(body []byte) (*FilteringRefreshResult, *Error) {
	var wireResult filteringRefreshResponse

	err := unmarshalFilteringObject(body, &wireResult)
	if err != nil {
		return nil, filteringJSONError(filteringRefreshOperation, http.MethodPost, err)
	}

	return &FilteringRefreshResult{Updated: wireResult.Updated}, nil
}

// assertFilteringFuzzRequestJSON checks presence-sensitive serialization for
// every filtering request model.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - models: The decoded request models to encode.
func assertFilteringFuzzRequestJSON(tb testing.TB, models filteringFuzzRequestModels) {
	tb.Helper()

	name := ""
	if models.add.Name != nil {
		name = *models.add.Name
	}

	filterURL := ""
	if models.add.URL != nil {
		filterURL = *models.add.URL
	}

	enabled := false
	if models.add.Whitelist != nil {
		enabled = *models.add.Whitelist
	}

	setData := &FilteringURLData{
		Enabled: enabled,
		Name:    name,
		URL:     filterURL,
	}
	setRequest := &SetFilteringURLRequest{
		Data:      setData,
		URL:       models.add.URL,
		Whitelist: models.add.Whitelist,
	}
	refreshRequest := &RefreshFilteringRequest{Whitelist: models.refresh.Whitelist}
	rulesRequest := &SetFilteringRulesRequest{Rules: models.rules.Rules}

	assertFilteringFuzzJSONFields(tb, models.config, map[string]bool{
		"enabled":  models.config.Enabled != nil,
		"interval": models.config.Interval != nil,
	})
	assertFilteringFuzzJSONFields(tb, models.add, map[string]bool{
		"name":      models.add.Name != nil,
		"url":       models.add.URL != nil,
		"whitelist": models.add.Whitelist != nil,
	})
	assertFilteringFuzzJSONFields(tb, models.remove, map[string]bool{
		"url":       models.remove.URL != nil,
		"whitelist": models.remove.Whitelist != nil,
	})
	assertFilteringFuzzJSONFields(tb, setData, map[string]bool{
		"enabled": true,
		"name":    true,
		"url":     true,
	})
	assertFilteringFuzzJSONFields(tb, setRequest, map[string]bool{
		"data":      true,
		"url":       setRequest.URL != nil,
		"whitelist": setRequest.Whitelist != nil,
	})
	assertFilteringFuzzJSONFields(tb, refreshRequest, map[string]bool{
		"whitelist": refreshRequest.Whitelist != nil,
	})
	assertFilteringFuzzJSONFields(tb, rulesRequest, map[string]bool{
		"rules": rulesRequest.Rules != nil,
	})
}

// assertFilteringFuzzJSONFields checks the exact key presence of one encoded
// filtering request model.
//
// Parameters:
//   - tb: The fuzz context receiving JSON failures.
//   - value: The request model to encode.
//   - expected: Whether each possible JSON key must be present.
func assertFilteringFuzzJSONFields(tb testing.TB, value any, expected map[string]bool) {
	tb.Helper()

	encoded, err := json.Marshal(value)
	if err != nil {
		tb.Fatalf("encode filtering request model: %v", err)
	}

	var fields map[string]any

	err = json.Unmarshal(encoded, &fields)
	if err != nil {
		tb.Fatalf("decode filtering request JSON: %v", err)
	}

	assertFilteringFuzzJSONPresence(tb, fields, expected, encoded)
}

// assertFilteringFuzzJSONPresence checks one decoded object's exact key set.
//
// Parameters:
//   - tb: The fuzz context receiving JSON failures.
//   - fields: The decoded request object.
//   - expected: Whether each possible JSON key must be present.
//   - encoded: The original JSON used for failure context.
func assertFilteringFuzzJSONPresence(
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
			tb.Fatalf("filtering request key %q presence = %t, want %t", key, present, mustBePresent)
		}
	}
	if len(fields) != expectedCount {
		tb.Fatalf("filtering request has %d keys, want %d: %s", len(fields), expectedCount, encoded)
	}
}

// exerciseFilteringFuzzMutations sends every filtering mutation through the
// rejecting in-memory transport and checks its structured request error.
//
// Parameters:
//   - t: The fuzz context receiving request failures.
//   - models: The decoded request models to send.
func exerciseFilteringFuzzMutations(t *testing.T, models filteringFuzzRequestModels) {
	t.Helper()

	client := newFilteringFuzzClient(t)
	ctx := t.Context()
	setRequest := &SetFilteringURLRequest{Data: &FilteringURLData{}}
	refreshRequest := &RefreshFilteringRequest{}
	rulesRequest := &SetFilteringRulesRequest{}

	operations := []struct {
		operation string
		call      func() error
	}{
		{operation: filteringConfigOperation, call: func() error {
			return client.UpdateFilteringConfig(ctx, models.config)
		}},
		{operation: filteringAddURLOperation, call: func() error {
			return client.AddFilteringURL(ctx, models.add)
		}},
		{operation: filteringRemoveURLOperation, call: func() error {
			return client.RemoveFilteringURL(ctx, models.remove)
		}},
		{operation: filteringSetURLOperation, call: func() error {
			return client.SetFilteringURL(ctx, setRequest)
		}},
		{operation: filteringSetURLOperation, call: func() error {
			return client.SetFilteringURL(ctx, nil)
		}},
		{operation: filteringRefreshOperation, call: func() error {
			_, err := client.RefreshFiltering(ctx, refreshRequest)

			return err
		}},
		{operation: filteringRefreshOperation, call: func() error {
			_, err := client.RefreshFiltering(ctx, nil)

			return err
		}},
		{operation: filteringSetRulesOperation, call: func() error {
			return client.SetFilteringRules(ctx, rulesRequest)
		}},
		{operation: filteringSetRulesOperation, call: func() error {
			return client.SetFilteringRules(ctx, nil)
		}},
	}
	for _, operation := range operations {
		err := operation.call()
		requireFilteringFuzzError(t, err, ErrorKindRequest, operation.operation, http.MethodPost)

		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s error does not preserve the transport cause: %v", operation.operation, err)
		}
	}
}

// requireFilteringFuzzError verifies that a filtering error has the required
// structured classification and metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - err: The error to inspect.
//   - kind: The expected structured error kind.
//   - operation: The expected operation name.
//   - method: The expected HTTP method.
func requireFilteringFuzzError(
	tb testing.TB,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) {
	tb.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	if !ok || clientErr == nil {
		tb.Fatalf("filtering error is not structured: %T %v", err, err)
	}
	if clientErr.Kind != kind || clientErr.Operation != operation || clientErr.Method != method {
		tb.Fatalf(
			"filtering error metadata = (%q, %q, %q), want (%q, %q, %q)",
			clientErr.Kind,
			clientErr.Operation,
			clientErr.Method,
			kind,
			operation,
			method,
		)
	}
	if clientErr.Err == nil {
		tb.Fatalf("structured filtering error %q has no cause", operation)
	}
}
