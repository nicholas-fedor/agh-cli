// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"
)

// statsFuzzRequestInputs contains the bounded values used by request fuzzing.
type statsFuzzRequestInputs struct {
	// enabled is the required configuration boolean.
	enabled bool
	// ignoredEnabled is the optional-boolean value.
	ignoredEnabled bool
	// ignoredEnabledMode selects an absent, false, or true optional boolean.
	ignoredEnabledMode uint8
	// ignoredMode selects an absent, empty, or populated ignored list.
	ignoredMode uint8
	// ignoredValue is the bounded ignored-list entry.
	ignoredValue string
	// recent is the query and configuration interval source value.
	recent int64
	// requestMode selects a nil, empty, or populated request.
	requestMode uint8
}

// statsFuzzMaxInputBytes bounds JSON and request-string work per fuzz input.
const statsFuzzMaxInputBytes = 16 << 10

// FuzzStatsResponses exercises statistics and configuration response contracts.
func FuzzStatsResponses(fuzz *testing.F) {
	addStatsFuzzResponseSeeds(fuzz)

	fuzz.Fuzz(func(t *testing.T, responseType uint8, body []byte) {
		body = body[:min(len(body), statsFuzzMaxInputBytes)]
		if !utf8.Valid(body) {
			return
		}

		exerciseStatsFuzzResponse(t, responseType, body)
	})
}

// FuzzStatsRequests exercises statistics request presence and validation offline.
func FuzzStatsRequests(fuzz *testing.F) {
	addStatsFuzzRequestSeeds(fuzz)

	fuzz.Fuzz(func(
		t *testing.T,
		recent int64,
		requestMode uint8,
		ignoredMode uint8,
		ignoredValue string,
		ignoredEnabledMode uint8,
		ignoredEnabled bool,
		enabled bool,
	) {
		if len(ignoredValue) > statsFuzzMaxInputBytes || !utf8.ValidString(ignoredValue) {
			return
		}

		exerciseStatsFuzzRequests(
			t,
			statsFuzzRequestInputs{
				enabled:            enabled,
				ignoredEnabled:     ignoredEnabled,
				ignoredEnabledMode: ignoredEnabledMode,
				ignoredMode:        ignoredMode,
				ignoredValue:       ignoredValue,
				recent:             recent,
				requestMode:        requestMode,
			},
		)
	})
}

// addStatsFuzzRequestSeeds registers deterministic request fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addStatsFuzzRequestSeeds(f *testing.F) {
	f.Helper()

	f.Add(int64(0), uint8(0), uint8(0), "", uint8(0), false, false)
	f.Add(int64(3_600_000), uint8(1), uint8(1), "", uint8(1), false, true)
	f.Add(
		int64(-1),
		uint8(2),
		uint8(2),
		"localhost",
		uint8(2),
		true,
		true,
	)
	f.Add(int64(7_776_000_000), uint8(2), uint8(0), "router.local", uint8(0), true, false)
}

// addStatsFuzzResponseSeeds registers deterministic response fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addStatsFuzzResponseSeeds(f *testing.F) {
	f.Helper()

	f.Add(uint8(0), []byte(`{}`))
	f.Add(uint8(0), []byte(
		`{"time_units":null,"num_dns_queries":null,"top_queried_domains":null,`+
			`"top_upstreams_responses":null,"top_upstreams_avg_time":null}`,
	))
	f.Add(uint8(0), []byte(
		`{"time_units":"hours","num_dns_queries":0,"avg_processing_time":0,`+
			`"top_queried_domains":[],"top_upstreams_responses":[],`+
			`"top_upstreams_avg_time":[],"dns_queries":[]}`,
	))
	f.Add(uint8(0), []byte(
		`{"time_units":"days","top_queried_domains":[{"example.org":1},null],`+
			`"top_upstreams_responses":[{"1.1.1.1":2}],`+
			`"top_upstreams_avg_time":[{"1.1.1.1":0.5}]}`,
	))
	f.Add(uint8(0), []byte(`{"time_units":"minutes"}`))
	f.Add(uint8(0), []byte(`{"time_units":0}`))
	f.Add(uint8(0), []byte(`{"top_upstreams_avg_time":`+statsFuzzUpstreamsJSON(101)))
	f.Add(uint8(0), []byte(`null`))
	f.Add(uint8(0), []byte(`[]`))
	f.Add(uint8(0), []byte(`{"num_dns_queries":`))
	f.Add(uint8(0), []byte(`{"num_dns_queries":1,"num_dns_queries":2}`))

	f.Add(uint8(1), []byte(`{"enabled":false,"interval":0,"anonymize_client_ip":false,"ignored":[]}`))
	f.Add(uint8(1), []byte(`{"enabled":true,"interval":1,"ignored":["localhost"]}`))
	f.Add(uint8(1), []byte(
		`{"enabled":true,"interval":0,"anonymize_client_ip":true,"ignored":[],`+
			`"ignored_enabled":false}`,
	))
	f.Add(uint8(1), []byte(
		`{"enabled":true,"interval":0,"anonymize_client_ip":true,"ignored":[],`+
			`"ignored_enabled":true}`,
	))
	f.Add(uint8(1), []byte(`{"interval":0,"ignored":[]}`))
	f.Add(uint8(1), []byte(`{"enabled":null,"interval":0,"ignored":[]}`))
	f.Add(uint8(1), []byte(`{"enabled":true,"interval":null,"ignored":[]}`))
	f.Add(uint8(1), []byte(`{"enabled":true,"interval":0,"ignored":null}`))
	f.Add(uint8(1), []byte(`{"enabled":1,"interval":0,"ignored":[]}`))
	f.Add(uint8(1), []byte(`null`))
	f.Add(uint8(1), []byte(`[]`))
	f.Add(uint8(1), []byte(`{"enabled":`))
	f.Add(uint8(1), []byte(`{"enabled":true,"enabled":false,"interval":0,"ignored":[]}`))
}

// statsFuzzUpstreamsJSON creates a deterministic upstream list at a requested size.
//
// Parameters:
//   - size: The number of upstream entries.
//
// Returns:
//   - upstreamJSON: The bounded JSON array.
func statsFuzzUpstreamsJSON(size int) string {
	return `[` + strings.TrimSuffix(strings.Repeat("{},", size), ",") + `]`
}

// newStatsFuzzClient creates a deterministic offline client for one response body.
//
// Parameters:
//   - responseBody: The bounded body returned for GET requests.
//   - captured: The optional destination for captured request metadata.
//
// Returns:
//   - client: An offline statistics client.
func newStatsFuzzClient(
	t *testing.T,
	responseBody []byte,
	captured *fuzzRequestCapture,
) *Client {
	t.Helper()

	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		if captured != nil {
			capture, err := captureFuzzRequest(request)
			if err != nil {
				return nil, err
			}

			*captured = capture
		}

		if request.Method == http.MethodGet {
			return fuzzHTTPResponse(request, http.StatusOK, jsonContentType, responseBody), nil
		}

		return fuzzHTTPResponse(request, http.StatusOK, "", nil), nil
	})

	return newFuzzClient(t, transport, max(int64(1), int64(len(responseBody))))
}

// exerciseStatsFuzzResponse dispatches one bounded response to its operation.
//
// Parameters:
//   - responseType: The response-operation selector.
//   - body: The bounded JSON response body.
func exerciseStatsFuzzResponse(t *testing.T, responseType uint8, body []byte) {
	t.Helper()

	client := newStatsFuzzClient(t, body, nil)

	switch responseType % 2 {
	case 0:
		exerciseStatisticsFuzzResult(t, client)
	case 1:
		exerciseStatsConfigFuzzResult(t, client)
	default:
		t.Fatalf("unreachable statistics response selector %d", responseType%2)
	}
}

// exerciseStatisticsFuzzResult checks statistics decoding and structured errors.
//
// Parameters:
//   - client: The offline statistics client.
func exerciseStatisticsFuzzResult(t *testing.T, client *Client) {
	t.Helper()

	result, err := client.Stats(t.Context(), nil)
	if err != nil {
		if result != nil {
			t.Fatal("statistics returned a result with a JSON error")
		}

		requireStatsFuzzJSONError(t, err, statsOperation)

		return
	}
	if result == nil {
		t.Fatal("statistics returned a nil result without an error")
	}

	validationErr := validateStats(result)
	if validationErr != nil {
		t.Fatalf("statistics returned invalid data: %v", validationErr)
	}
}

// exerciseStatsConfigFuzzResult checks configuration decoding and JSON errors.
//
// Parameters:
//   - client: The offline statistics client.
func exerciseStatsConfigFuzzResult(t *testing.T, client *Client) {
	t.Helper()

	result, err := client.GetStatsConfig(t.Context())
	if err != nil {
		if result != nil {
			t.Fatal("statistics configuration returned a result with a JSON error")
		}

		requireStatsFuzzJSONError(t, err, getStatsConfigOperation)

		return
	}
	if result == nil || result.Ignored == nil {
		t.Fatal("statistics configuration omitted required data on success")
	}
}

// requireStatsFuzzJSONError verifies one statistics JSON error contract.
//
// Parameters:
//   - err: The error returned by the statistics operation.
//   - operation: The expected operation name.
func requireStatsFuzzJSONError(t *testing.T, err error, operation string) {
	t.Helper()

	clientErr := requireFuzzError(t, err, ErrorKindJSON, operation, http.MethodGet)
	if clientErr.Err == nil {
		t.Fatalf("structured statistics error %q has no cause", operation)
	}
}

// exerciseStatsFuzzRequests checks all statistics request shapes without sockets.
//
// Parameters:
//   - inputs: The bounded request inputs.
func exerciseStatsFuzzRequests(t *testing.T, inputs statsFuzzRequestInputs) {
	t.Helper()

	captured := new(fuzzRequestCapture)
	client := newStatsFuzzClient(t, []byte(`{}`), captured)
	exerciseStatsFuzzReadRequests(t, client, captured, statsFuzzRequest(inputs))

	*captured = fuzzRequestCapture{}
	exerciseStatsFuzzConfigRequest(t, client, captured, inputs)
}

// exerciseStatsFuzzReadRequests checks statistics and reset request shapes.
//
// Parameters:
//   - client: The offline statistics client.
//   - captured: The captured request destination.
//   - request: The statistics request under test.
func exerciseStatsFuzzReadRequests(
	t *testing.T,
	client *Client,
	captured *fuzzRequestCapture,
	request *StatsRequest,
) {
	t.Helper()

	_, err := client.Stats(t.Context(), request)
	if err != nil {
		t.Fatalf("valid statistics request returned an error: %v", err)
	}

	assertStatsFuzzReadRequest(t, *captured, request)

	err = client.StatsReset(t.Context())
	if err != nil {
		t.Fatalf("statistics reset returned an error: %v", err)
	}

	assertStatsFuzzResetRequest(t, *captured)
}

// exerciseStatsFuzzConfigRequest checks configuration presence and serialization.
//
// Parameters:
//   - client: The offline statistics client.
//   - captured: The captured request destination.
//   - inputs: The bounded request inputs.
func exerciseStatsFuzzConfigRequest(
	t *testing.T,
	client *Client,
	captured *fuzzRequestCapture,
	inputs statsFuzzRequestInputs,
) {
	t.Helper()

	config, ignoredPresent := statsFuzzConfig(inputs)
	err := client.PutStatsConfig(t.Context(), config)
	if !ignoredPresent {
		requireStatsFuzzRequestError(t, err, putStatsConfigOperation, http.MethodPut)

		if !errors.Is(err, errRequiredStatsConfigField) {
			t.Fatalf("statistics config error does not preserve required-field validation: %v", err)
		}
		if captured.method != "" {
			t.Fatalf("statistics config sent a request without required fields: %+v", *captured)
		}

		return
	}
	if err != nil {
		t.Fatalf("valid statistics config returned an error: %v", err)
	}

	assertStatsFuzzConfigRequest(t, *captured, config)
}

// statsFuzzRequest creates a nil, empty, or populated statistics request.
//
// Parameters:
//   - inputs: The bounded request inputs.
//
// Returns:
//   - request: The selected statistics request.
func statsFuzzRequest(inputs statsFuzzRequestInputs) *StatsRequest {
	switch inputs.requestMode % 3 {
	case 0:
		return nil
	case 1:
		return &StatsRequest{}
	case 2:
		return &StatsRequest{Recent: new(inputs.recent)}
	default:
		return &StatsRequest{Recent: new(int64(0))}
	}
}

// assertStatsFuzzReadRequest verifies body absence and recent-parameter presence.
//
// Parameters:
//   - captured: The captured HTTP request metadata and body.
//   - request: The statistics request expected on the wire.
func assertStatsFuzzReadRequest(t *testing.T, captured fuzzRequestCapture, request *StatsRequest) {
	t.Helper()

	expectedQuery := ""
	if request != nil && request.Recent != nil {
		expectedQuery = "recent=" + strconv.FormatInt(*request.Recent, 10)
	}
	if captured.method != http.MethodGet ||
		captured.path != "/api/control/stats" ||
		captured.query != expectedQuery ||
		len(captured.body) != 0 ||
		captured.contentType != "" {
		t.Fatalf("statistics request shape is incorrect: %+v", captured)
	}
}

// assertStatsFuzzResetRequest verifies the bodyless reset request.
//
// Parameters:
//   - captured: The captured HTTP request metadata and body.
func assertStatsFuzzResetRequest(t *testing.T, captured fuzzRequestCapture) {
	t.Helper()

	if captured.method != http.MethodPost ||
		captured.path != "/api/control/stats_reset" ||
		captured.query != "" ||
		len(captured.body) != 0 ||
		captured.contentType != "" {
		t.Fatalf("statistics reset request shape is incorrect: %+v", captured)
	}
}

// statsFuzzConfig creates a required-field configuration with optional presence.
//
// Parameters:
//   - inputs: The bounded request inputs.
//
// Returns:
//   - config: The statistics configuration.
//   - present: Whether the required ignored list is present.
func statsFuzzConfig(inputs statsFuzzRequestInputs) (StatsConfig, bool) {
	config := StatsConfig{
		Enabled:  inputs.enabled,
		Ignored:  nil,
		Interval: float64(inputs.recent),
	}

	ignoredMode := inputs.ignoredMode % 3
	if ignoredMode == 0 {
		return config, false
	}
	if ignoredMode == 1 {
		config.Ignored = []string{}
	} else {
		config.Ignored = []string{inputs.ignoredValue}
	}

	switch inputs.ignoredEnabledMode % 3 {
	case 1:
		config.IgnoredEnabled = new(false)
	case 2:
		config.IgnoredEnabled = new(inputs.ignoredEnabled)
	default:
		config.IgnoredEnabled = new(!inputs.ignoredEnabled)
	}

	return config, true
}

// assertStatsFuzzConfigRequest verifies required and optional request fields.
//
// Parameters:
//   - captured: The captured HTTP request metadata and body.
//   - config: The configuration expected on the wire.
func assertStatsFuzzConfigRequest(t *testing.T, captured fuzzRequestCapture, config StatsConfig) {
	t.Helper()

	if captured.method != http.MethodPut ||
		captured.path != "/api/control/stats/config/update" ||
		captured.query != "" ||
		captured.contentType != jsonContentType {
		t.Fatalf("statistics config request shape is incorrect: %+v", captured)
	}

	var fields map[string]any

	err := json.Unmarshal(captured.body, &fields)
	if err != nil {
		t.Fatalf("decode statistics config request: %v", err)
	}

	assertStatsFuzzConfigPresence(t, fields, config.IgnoredEnabled, captured.body)
	assertStatsFuzzConfigValues(t, fields, config, captured.body)
}

// assertStatsFuzzConfigPresence checks required and optional encoded field presence.
//
// Parameters:
//   - fields: The decoded request object.
//   - optionalValue: The optional encoded boolean pointer.
//   - body: The encoded request body used for failure context.
func assertStatsFuzzConfigPresence(
	t *testing.T,
	fields map[string]any,
	optionalValue *bool,
	body []byte,
) {
	t.Helper()

	expectedCount := 3
	if optionalValue != nil {
		expectedCount++
	}
	if len(fields) != expectedCount {
		t.Fatalf("statistics config has %d fields, want %d: %s", len(fields), expectedCount, body)
	}

	for _, key := range []string{safetyEnabledKey, adguardTestIntervalKey, "ignored"} {
		if _, present := fields[key]; !present {
			t.Fatalf("statistics config omitted required field %q: %s", key, body)
		}
	}
}

// assertStatsFuzzConfigValues checks required and optional encoded values.
//
// Parameters:
//   - fields: The decoded request object.
//   - config: The expected configuration values.
//   - body: The encoded request body used for failure context.
func assertStatsFuzzConfigValues(
	t *testing.T,
	fields map[string]any,
	config StatsConfig,
	body []byte,
) {
	t.Helper()

	enabled, enabledOK := fields["enabled"].(bool)
	interval, intervalOK := fields["interval"].(float64)
	ignored, ignoredOK := fields["ignored"].([]any)
	if !enabledOK || enabled != config.Enabled ||
		!intervalOK || interval != config.Interval ||
		!ignoredOK || len(ignored) != len(config.Ignored) {
		t.Fatalf("statistics config values are incorrect: %s", body)
	}

	assertStatsFuzzIgnored(t, ignored, config.Ignored, body)
	assertStatsFuzzOptionalBool(
		t,
		fields,
		"ignored_enabled",
		config.IgnoredEnabled,
		"statistics config",
		body,
	)
}

// assertStatsFuzzIgnored checks one encoded ignored list.
//
// Parameters:
//   - actual: The decoded ignored-list values.
//   - expected: The expected ignored-list values.
//   - body: The encoded request body used for failure context.
func assertStatsFuzzIgnored(t *testing.T, actual []any, expected []string, body []byte) {
	t.Helper()

	for index, expectedValue := range expected {
		actualValue, ok := actual[index].(string)
		if !ok || actualValue != expectedValue {
			t.Fatalf("statistics config ignored[%d] is incorrect: %s", index, body)
		}
	}
}

// assertStatsFuzzOptionalBool checks one optional encoded boolean.
//
// Parameters:
//   - fields: The decoded request object.
//   - key: The optional field name.
//   - expected: The expected optional boolean pointer.
//   - name: The model name used for failure context.
//   - body: The encoded request body used for failure context.
func assertStatsFuzzOptionalBool(
	t *testing.T,
	fields map[string]any,
	key string,
	expected *bool,
	name string,
	body []byte,
) {
	t.Helper()

	actual, present := fields[key]
	if present != (expected != nil) {
		t.Fatalf("%s %s presence is %t: %s", name, key, present, body)
	}
	if expected != nil {
		actualValue, ok := actual.(bool)
		if !ok || actualValue != *expected {
			t.Fatalf("%s %s is incorrect: %s", name, key, body)
		}
	}
}

// requireStatsFuzzRequestError verifies one structured statistics request error.
//
// Parameters:
//   - err: The error returned by the statistics operation.
//   - operation: The expected operation name.
//   - method: The expected HTTP method.
func requireStatsFuzzRequestError(t *testing.T, err error, operation, method string) {
	t.Helper()

	clientErr := requireFuzzError(t, err, ErrorKindRequest, operation, method)
	if clientErr.Err == nil {
		t.Fatalf("structured statistics request error %q has no cause", operation)
	}
}
