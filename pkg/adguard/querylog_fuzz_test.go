// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"unicode/utf8"
)

// queryLogFuzzRequestInputs contains the bounded values used by request fuzzing.
type queryLogFuzzRequestInputs struct {
	// ignoredEnabled is the optional-boolean value.
	ignoredEnabled bool
	// ignoredEnabledMode selects an absent, false, or true optional boolean.
	ignoredEnabledMode uint8
	// ignoredMode selects an absent, empty, or populated ignored list.
	ignoredMode uint8
	// ignoredValue is the bounded ignored-list entry.
	ignoredValue string
	// limit is the query limit.
	limit int32
	// offset is the query offset.
	offset int32
	// olderThan is the bounded timestamp query value.
	olderThan string
	// reasonValid selects valid or invalid reason handling.
	reasonValid bool
	// reasonValue is the bounded candidate reason.
	reasonValue string
	// requestMode selects a nil, empty, or populated request.
	requestMode uint8
	// search is the bounded search query value.
	search string
}

// queryLogFuzzMaxInputBytes bounds JSON and request-string work per fuzz input.
const queryLogFuzzMaxInputBytes = 16 << 10

// adguardTestIntervalKey is the interval field name in decoded request objects.
const adguardTestIntervalKey = "interval"

// FuzzQueryLogResponses exercises query-log and configuration response contracts.
func FuzzQueryLogResponses(fuzz *testing.F) {
	addQueryLogFuzzResponseSeeds(fuzz)

	fuzz.Fuzz(func(t *testing.T, responseType uint8, body []byte) {
		body = queryLogFuzzBoundedBody(body)
		if !utf8.Valid(body) {
			return
		}

		exerciseQueryLogFuzzResponse(t, responseType, body)
	})
}

// FuzzQueryLogRequests exercises query-log request presence and validation offline.
func FuzzQueryLogRequests(fuzz *testing.F) {
	addQueryLogFuzzRequestSeeds(fuzz)

	fuzz.Fuzz(func(
		t *testing.T,
		olderThan string,
		search string,
		offset int32,
		limit int32,
		reasonValue string,
		reasonValid bool,
		requestMode uint8,
		ignoredMode uint8,
		ignoredValue string,
		ignoredEnabledMode uint8,
		ignoredEnabled bool,
	) {
		if !queryLogFuzzInputBounded(olderThan, search, reasonValue, ignoredValue) {
			return
		}

		exerciseQueryLogFuzzRequests(
			t,
			queryLogFuzzRequestInputs{
				ignoredEnabled:     ignoredEnabled,
				ignoredEnabledMode: ignoredEnabledMode,
				ignoredMode:        ignoredMode,
				ignoredValue:       ignoredValue,
				limit:              limit,
				offset:             offset,
				olderThan:          olderThan,
				reasonValid:        reasonValid,
				reasonValue:        reasonValue,
				requestMode:        requestMode,
				search:             search,
			},
		)
	})
}

// addQueryLogFuzzRequestSeeds registers deterministic request fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addQueryLogFuzzRequestSeeds(f *testing.F) {
	f.Helper()

	f.Add(
		"",
		"",
		int32(0),
		int32(0),
		"",
		true,
		uint8(0),
		uint8(0),
		"",
		uint8(0),
		false,
	)
	f.Add(
		"2026-09-25T01:00:00Z",
		"example.org",
		int32(-1),
		int32(1),
		"future",
		true,
		uint8(1),
		uint8(1),
		"",
		uint8(1),
		false,
	)
	f.Add(
		"",
		"needle",
		int32(1),
		int32(-1),
		"NotFilteredNotFound",
		true,
		uint8(2),
		uint8(2),
		"localhost",
		uint8(2),
		true,
	)
	f.Add(
		"older",
		"search",
		int32(0),
		int32(0),
		"invalid reason",
		false,
		uint8(2),
		uint8(0),
		"host",
		uint8(0),
		true,
	)
}

// addQueryLogFuzzResponseSeeds registers deterministic response fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addQueryLogFuzzResponseSeeds(f *testing.F) {
	f.Helper()

	f.Add(uint8(0), []byte(`{}`))
	f.Add(uint8(0), []byte(`{"oldest":null,"data":null}`))
	f.Add(uint8(0), []byte(`{"oldest":"","data":[]}`))
	f.Add(uint8(0), []byte(
		`{"oldest":"2026-09-25T01:00:00Z","data":[{`+
			`"reason":"NotFilteredNotFound","rules":[{"filter_list_id":0,"text":""}],`+
			`"client_info":{"disallowed":false,"disallowed_rule":"","name":"",`+
			`"whois":{"city":null,"country":"","orgname":"Example Network"}}}]}`,
	))
	f.Add(uint8(0), []byte(`{"data":[null]}`))
	f.Add(uint8(0), []byte(`{"data":[{"reason":"FutureReason"}]}`))
	f.Add(uint8(0), []byte(`{"data":[{"rules":[null]}]}`))
	f.Add(uint8(0), []byte(`{"data":[{"client_info":{"disallowed":false}}]}`))
	f.Add(uint8(0), []byte(`null`))
	f.Add(uint8(0), []byte(`[]`))
	f.Add(uint8(0), []byte(`{"data":`))
	f.Add(uint8(0), []byte(`{"data":[],"data":null}`))

	f.Add(uint8(1), []byte(
		`{"enabled":false,"interval":0,"anonymize_client_ip":false,`+
			`"ignored":[],"ignored_enabled":null}`,
	))
	f.Add(uint8(1), []byte(
		`{"enabled":true,"interval":1,"anonymize_client_ip":true,`+
			`"ignored":["localhost"],"ignored_enabled":false}`,
	))
	f.Add(uint8(1), []byte(`{"enabled":true,"interval":1,"anonymize_client_ip":true}`))
	f.Add(uint8(1), []byte(
		`{"enabled":true,"interval":null,"anonymize_client_ip":true,"ignored":[]}`,
	))
	f.Add(uint8(1), []byte(`{"enabled":null,"interval":1,"anonymize_client_ip":true,"ignored":[]}`))
	f.Add(uint8(1), []byte(
		`{"enabled":true,"interval":1,"anonymize_client_ip":null,"ignored":[]}`,
	))
	f.Add(uint8(1), []byte(`{"enabled":true,"interval":1,"anonymize_client_ip":true,"ignored":null}`))
	f.Add(uint8(1), []byte(`{"enabled":"true","interval":1,"anonymize_client_ip":true,"ignored":[]}`))
	f.Add(uint8(1), []byte(`null`))
	f.Add(uint8(1), []byte(`[]`))
	f.Add(uint8(1), []byte(`{"enabled":`))
	f.Add(uint8(1), []byte(
		`{"enabled":true,"enabled":false,"interval":1,`+
			`"anonymize_client_ip":true,"ignored":[]}`,
	))
}

// queryLogFuzzBoundedBody limits a fuzz-derived response to the per-input budget.
//
// Parameters:
//   - body: The generated response body.
//
// Returns:
//   - bounded: The response prefix within the input budget.
func queryLogFuzzBoundedBody(body []byte) []byte {
	return body[:min(len(body), queryLogFuzzMaxInputBytes)]
}

// queryLogFuzzInputBounded reports whether request strings are valid UTF-8 and bounded.
//
// Parameters:
//   - olderThan: The generated timestamp query value.
//   - search: The generated search query value.
//   - reasonValue: The generated reason value.
//   - ignoredValue: The generated ignored-list entry.
//
// Returns:
//   - bounded: Whether every string satisfies the input budget and encoding contract.
func queryLogFuzzInputBounded(olderThan, search, reasonValue, ignoredValue string) bool {
	return len(olderThan)+len(search)+len(reasonValue)+len(ignoredValue) <= queryLogFuzzMaxInputBytes &&
		utf8.ValidString(olderThan) &&
		utf8.ValidString(search) &&
		utf8.ValidString(reasonValue) &&
		utf8.ValidString(ignoredValue)
}

// newQueryLogFuzzClient creates a deterministic offline client for one response body.
//
// Parameters:
//   - responseBody: The bounded body returned for GET requests.
//   - captured: The optional destination for captured request metadata.
//
// Returns:
//   - client: An offline query-log client.
func newQueryLogFuzzClient(
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

// exerciseQueryLogFuzzResponse dispatches one bounded response to its operation.
//
// Parameters:
//   - responseType: The response-operation selector.
//   - body: The bounded JSON response body.
func exerciseQueryLogFuzzResponse(t *testing.T, responseType uint8, body []byte) {
	t.Helper()

	client := newQueryLogFuzzClient(t, body, nil)

	switch responseType % 2 {
	case 0:
		exerciseQueryLogFuzzResult(t, client, body)
	case 1:
		exerciseQueryLogConfigFuzzResult(t, client)
	default:
		t.Fatalf("unreachable query log response selector %d", responseType%2)
	}
}

// exerciseQueryLogFuzzResult checks query-log decoding and structured JSON errors.
//
// Parameters:
//   - client: The offline query-log client.
//   - body: The bounded JSON response body.
func exerciseQueryLogFuzzResult(t *testing.T, client *Client, body []byte) {
	t.Helper()

	result, err := client.QueryLog(t.Context(), &QueryLogRequest{})
	if err != nil {
		if result != nil {
			t.Fatal("query log returned a result with a JSON error")
		}

		requireQueryLogFuzzJSONError(t, err, queryLogOperation)

		return
	}
	if result == nil {
		t.Fatal("query log returned a nil result without an error")
	}

	assertQueryLogFuzzResult(t, result, body)
}

// exerciseQueryLogConfigFuzzResult checks configuration decoding and JSON errors.
//
// Parameters:
//   - client: The offline query-log client.
func exerciseQueryLogConfigFuzzResult(t *testing.T, client *Client) {
	t.Helper()

	result, err := client.GetQueryLogConfig(t.Context())
	if err != nil {
		if result != nil {
			t.Fatal("query log configuration returned a result with a JSON error")
		}

		requireQueryLogFuzzJSONError(t, err, getQueryLogConfigOperation)

		return
	}
	if result == nil || result.Ignored == nil {
		t.Fatal("query log configuration omitted required data on success")
	}
}

// assertQueryLogFuzzResult checks constraints promised by a successful query log.
//
// Parameters:
//   - result: The decoded query log.
//   - body: The bounded JSON response body used for failure context.
func assertQueryLogFuzzResult(t *testing.T, result *QueryLog, body []byte) {
	t.Helper()

	if result.Data == nil {
		return
	}

	entries := *result.Data
	for index := range entries {
		assertQueryLogFuzzEntry(t, &entries[index], index, body)
	}
}

// assertQueryLogFuzzEntry checks constraints for one successful query-log entry.
//
// Parameters:
//   - entry: The decoded query-log entry.
//   - index: The entry index used for failure context.
//   - body: The bounded JSON response body used for failure context.
func assertQueryLogFuzzEntry(t *testing.T, entry *QueryLogEntry, index int, body []byte) {
	t.Helper()

	if entry.Reason != nil && !validFilteringReason(*entry.Reason) {
		t.Fatalf("query log entry %d has invalid reason %q", index, *entry.Reason)
	}
	if entry.Rules != nil {
		assertQueryLogFuzzRules(t, *entry.Rules, index, body)
	}
	if entry.ClientInfo != nil && entry.ClientInfo.Whois == nil {
		t.Fatalf("query log entry %d has incomplete client information in %s", index, body)
	}
}

// assertQueryLogFuzzRules checks that a successful entry contains no nil rules.
//
// Parameters:
//   - rules: The decoded query-log rules.
//   - entryIndex: The containing entry index used for failure context.
//   - body: The bounded JSON response body used for failure context.
func assertQueryLogFuzzRules(t *testing.T, rules []*QueryLogRule, entryIndex int, body []byte) {
	t.Helper()

	for index, rule := range rules {
		if rule == nil {
			t.Fatalf("query log entry %d has nil rule %d in %s", entryIndex, index, body)
		}
	}
}

// requireQueryLogFuzzJSONError verifies one query-log JSON error contract.
//
// Parameters:
//   - err: The error returned by the query-log operation.
//   - operation: The expected operation name.
func requireQueryLogFuzzJSONError(t *testing.T, err error, operation string) {
	t.Helper()

	clientErr := requireFuzzError(t, err, ErrorKindJSON, operation, http.MethodGet)
	if clientErr.Err == nil {
		t.Fatalf("structured query log error %q has no cause", operation)
	}
}

// exerciseQueryLogFuzzRequests checks all query-log request shapes without sockets.
//
// Parameters:
//   - inputs: The bounded request inputs.
func exerciseQueryLogFuzzRequests(t *testing.T, inputs queryLogFuzzRequestInputs) {
	t.Helper()

	captured := new(fuzzRequestCapture)
	client := newQueryLogFuzzClient(t, []byte(`{}`), captured)
	request := queryLogFuzzRequest(inputs)
	exerciseQueryLogFuzzReadRequest(t, client, captured, request, inputs.reasonValid)

	err := client.QueryLogClear(t.Context())
	if err != nil {
		t.Fatalf("query log clear returned an error: %v", err)
	}

	assertQueryLogFuzzClearRequest(t, *captured)

	*captured = fuzzRequestCapture{}
	exerciseQueryLogFuzzConfigRequest(t, client, captured, inputs)
}

// exerciseQueryLogFuzzReadRequest checks one query-log read request shape.
//
// Parameters:
//   - client: The offline query-log client.
//   - captured: The captured request destination.
//   - request: The query-log request under test.
//   - reasonValid: Whether the generated reason branch should succeed.
func exerciseQueryLogFuzzReadRequest(
	t *testing.T,
	client *Client,
	captured *fuzzRequestCapture,
	request *QueryLogRequest,
	reasonValid bool,
) {
	t.Helper()

	_, err := client.QueryLog(t.Context(), request)
	invalidReason := request != nil && !reasonValid && len(request.Reasons) != 0
	if invalidReason {
		assertQueryLogFuzzInvalidReason(t, err, *captured)

		return
	}
	if err != nil {
		t.Fatalf("valid query log request returned an error: %v", err)
	}

	assertQueryLogFuzzReadRequest(t, *captured, request)
}

// assertQueryLogFuzzInvalidReason checks local reason validation and request absence.
//
// Parameters:
//   - err: The error returned by QueryLog.
//   - captured: The request capture, which must remain empty.
func assertQueryLogFuzzInvalidReason(t *testing.T, err error, captured fuzzRequestCapture) {
	t.Helper()

	requireQueryLogFuzzRequestError(t, err, queryLogOperation, http.MethodGet)

	if !errors.Is(err, errInvalidQueryLogReason) {
		t.Fatalf("query log error does not preserve reason validation: %v", err)
	}
	if captured.method != "" {
		t.Fatalf("query log sent a request with an invalid reason: %+v", captured)
	}
}

// exerciseQueryLogFuzzConfigRequest checks configuration presence and serialization.
//
// Parameters:
//   - client: The offline query-log client.
//   - captured: The captured request destination.
//   - inputs: The bounded request inputs.
func exerciseQueryLogFuzzConfigRequest(
	t *testing.T,
	client *Client,
	captured *fuzzRequestCapture,
	inputs queryLogFuzzRequestInputs,
) {
	t.Helper()

	config, ignoredPresent := queryLogFuzzConfig(inputs)
	err := client.PutQueryLogConfig(t.Context(), config)
	if !ignoredPresent {
		requireQueryLogFuzzRequestError(t, err, putQueryLogConfigOperation, http.MethodPut)

		if !errors.Is(err, errRequiredQueryLogField) {
			t.Fatalf("query log config error does not preserve required-field validation: %v", err)
		}
		if captured.method != "" {
			t.Fatalf("query log config sent a request without required fields: %+v", *captured)
		}

		return
	}
	if err != nil {
		t.Fatalf("valid query log config returned an error: %v", err)
	}

	assertQueryLogFuzzConfigRequest(t, *captured, config)
}

// queryLogFuzzRequest creates a nil, empty, or populated query request.
//
// Parameters:
//   - inputs: The bounded request inputs.
//
// Returns:
//   - request: The selected query-log request.
func queryLogFuzzRequest(inputs queryLogFuzzRequestInputs) *QueryLogRequest {
	switch inputs.requestMode % 3 {
	case 0:
		return nil
	case 1:
		return &QueryLogRequest{}
	case 2:
		return &QueryLogRequest{
			Limit:     new(inputs.limit),
			Offset:    new(inputs.offset),
			OlderThan: new(inputs.olderThan),
			Reasons:   queryLogFuzzReasons(inputs),
			Search:    new(inputs.search),
		}
	default:
		return &QueryLogRequest{Search: new("")}
	}
}

// queryLogFuzzReasons creates valid or deliberately invalid reason values.
//
// Parameters:
//   - inputs: The bounded request inputs.
//
// Returns:
//   - reasons: The generated reason list.
func queryLogFuzzReasons(inputs queryLogFuzzRequestInputs) []FilteringReason {
	if inputs.reasonValid {
		return queryLogFuzzValidReasons(inputs.ignoredEnabledMode)
	}

	return []FilteringReason{queryLogFuzzInvalidReason(inputs.reasonValue)}
}

// queryLogFuzzValidReasons creates one or two valid filtering reasons.
//
// Parameters:
//   - selector: The fuzz-derived list-shape selector.
//
// Returns:
//   - reasons: The valid reason list.
func queryLogFuzzValidReasons(selector uint8) []FilteringReason {
	if selector%2 == 0 {
		return []FilteringReason{FilteringReasonNotFilteredNotFound}
	}

	return []FilteringReason{FilteringReasonFilteredBlackList, FilteringReasonRewrite}
}

// queryLogFuzzInvalidReason converts a valid candidate into an invalid reason.
//
// Parameters:
//   - value: The generated candidate reason.
//
// Returns:
//   - reason: A reason rejected by QueryLog request validation.
func queryLogFuzzInvalidReason(value string) FilteringReason {
	reason := FilteringReason(value)
	if validFilteringReason(reason) {
		reason = FilteringReason("FutureReason")
	}

	return reason
}

// assertQueryLogFuzzReadRequest verifies body absence and exact query presence.
//
// Parameters:
//   - captured: The captured HTTP request metadata and body.
//   - request: The query-log request expected on the wire.
func assertQueryLogFuzzReadRequest(t *testing.T, captured fuzzRequestCapture, request *QueryLogRequest) {
	t.Helper()

	expectedQuery := queryLogFuzzExpectedQuery(request)
	if captured.method != http.MethodGet ||
		captured.path != "/api/control/querylog" ||
		captured.query != expectedQuery ||
		len(captured.body) != 0 ||
		captured.contentType != "" {
		t.Fatalf("query log request shape is incorrect: %+v", captured)
	}
}

// queryLogFuzzExpectedQuery encodes the query parameters expected from a request.
//
// Parameters:
//   - request: The optional query-log request.
//
// Returns:
//   - expectedQuery: The encoded query string.
func queryLogFuzzExpectedQuery(request *QueryLogRequest) string {
	expected := make(url.Values)
	if request == nil {
		return expected.Encode()
	}
	if request.OlderThan != nil {
		expected.Set("older_than", *request.OlderThan)
	}
	if request.Offset != nil {
		expected.Set("offset", strconv.FormatInt(int64(*request.Offset), 10))
	}
	if request.Limit != nil {
		expected.Set("limit", strconv.FormatInt(int64(*request.Limit), 10))
	}
	if request.Search != nil {
		expected.Set("search", *request.Search)
	}

	for _, reason := range request.Reasons {
		expected.Add("reason", string(reason))
	}

	return expected.Encode()
}

// assertQueryLogFuzzClearRequest verifies the bodyless clear request.
//
// Parameters:
//   - captured: The captured HTTP request metadata and body.
func assertQueryLogFuzzClearRequest(t *testing.T, captured fuzzRequestCapture) {
	t.Helper()

	if captured.method != http.MethodPost ||
		captured.path != "/api/control/querylog_clear" ||
		captured.query != "" ||
		len(captured.body) != 0 ||
		captured.contentType != "" {
		t.Fatalf("query log clear request shape is incorrect: %+v", captured)
	}
}

// queryLogFuzzConfig creates a required-field configuration with optional presence.
//
// Parameters:
//   - inputs: The bounded request inputs.
//
// Returns:
//   - config: The query-log configuration.
//   - present: Whether the required ignored list is present.
func queryLogFuzzConfig(inputs queryLogFuzzRequestInputs) (QueryLogConfig, bool) {
	config := QueryLogConfig{
		AnonymizeClientIP: inputs.ignoredEnabled,
		Enabled:           !inputs.ignoredEnabled,
		Interval:          float64(inputs.limit),
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

// assertQueryLogFuzzConfigRequest verifies required and optional request fields.
//
// Parameters:
//   - captured: The captured HTTP request metadata and body.
//   - config: The configuration expected on the wire.
func assertQueryLogFuzzConfigRequest(
	t *testing.T,
	captured fuzzRequestCapture,
	config QueryLogConfig,
) {
	t.Helper()

	if captured.method != http.MethodPut ||
		captured.path != "/api/control/querylog/config/update" ||
		captured.query != "" ||
		captured.contentType != jsonContentType {
		t.Fatalf("query log config request shape is incorrect: %+v", captured)
	}

	var fields map[string]any

	err := json.Unmarshal(captured.body, &fields)
	if err != nil {
		t.Fatalf("decode query log config request: %v", err)
	}

	assertQueryLogFuzzConfigPresence(t, fields, config.IgnoredEnabled, captured.body)
	assertQueryLogFuzzConfigValues(t, fields, config, captured.body)
}

// assertQueryLogFuzzConfigPresence checks required and optional encoded field presence.
//
// Parameters:
//   - fields: The decoded request object.
//   - optionalValue: The optional encoded boolean pointer.
//   - body: The encoded request body used for failure context.
func assertQueryLogFuzzConfigPresence(
	t *testing.T,
	fields map[string]any,
	optionalValue *bool,
	body []byte,
) {
	t.Helper()

	expectedCount := 4
	if optionalValue != nil {
		expectedCount++
	}
	if len(fields) != expectedCount {
		t.Fatalf("query log config has %d fields, want %d: %s", len(fields), expectedCount, body)
	}

	for _, key := range []string{
		safetyEnabledKey,
		adguardTestIntervalKey,
		"anonymize_client_ip",
		"ignored",
	} {
		if _, present := fields[key]; !present {
			t.Fatalf("query log config omitted required field %q: %s", key, body)
		}
	}
}

// assertQueryLogFuzzConfigValues checks required and optional encoded values.
//
// Parameters:
//   - fields: The decoded request object.
//   - config: The expected configuration values.
//   - body: The encoded request body used for failure context.
func assertQueryLogFuzzConfigValues(
	t *testing.T,
	fields map[string]any,
	config QueryLogConfig,
	body []byte,
) {
	t.Helper()

	enabled, enabledOK := fields["enabled"].(bool)
	interval, intervalOK := fields["interval"].(float64)
	ignored, ignoredOK := fields["ignored"].([]any)
	if !enabledOK || enabled != config.Enabled ||
		!intervalOK || interval != config.Interval ||
		!ignoredOK || len(ignored) != len(config.Ignored) {
		t.Fatalf("query log config values are incorrect: %s", body)
	}

	assertQueryLogFuzzIgnored(t, ignored, config.Ignored, body)
	assertQueryLogFuzzOptionalBool(
		t,
		fields,
		"ignored_enabled",
		config.IgnoredEnabled,
		"query log config",
		body,
	)
}

// assertQueryLogFuzzIgnored checks one encoded ignored list.
//
// Parameters:
//   - actual: The decoded ignored-list values.
//   - expected: The expected ignored-list values.
//   - body: The encoded request body used for failure context.
func assertQueryLogFuzzIgnored(t *testing.T, actual []any, expected []string, body []byte) {
	t.Helper()

	for index, expectedValue := range expected {
		actualValue, ok := actual[index].(string)
		if !ok || actualValue != expectedValue {
			t.Fatalf("query log config ignored[%d] is incorrect: %s", index, body)
		}
	}
}

// assertQueryLogFuzzOptionalBool checks one optional encoded boolean.
//
// Parameters:
//   - fields: The decoded request object.
//   - key: The optional field name.
//   - expected: The expected optional boolean pointer.
//   - name: The model name used for failure context.
//   - body: The encoded request body used for failure context.
func assertQueryLogFuzzOptionalBool(
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

// requireQueryLogFuzzRequestError verifies one structured query-log request error.
//
// Parameters:
//   - err: The error returned by the query-log operation.
//   - operation: The expected operation name.
//   - method: The expected HTTP method.
func requireQueryLogFuzzRequestError(
	t *testing.T,
	err error,
	operation string,
	method string,
) {
	t.Helper()

	clientErr := requireFuzzError(t, err, ErrorKindRequest, operation, method)
	if clientErr.Err == nil {
		t.Fatalf("structured query log request error %q has no cause", operation)
	}
}
