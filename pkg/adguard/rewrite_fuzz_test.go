// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"net/http"
	"testing"
)

// rewriteFuzzTransport rejects every request before it can reach a socket.
type rewriteFuzzTransport struct{}

// rewriteFuzzMaxInputBytes bounds JSON parsing and allocation per fuzz input.
const rewriteFuzzMaxInputBytes = 16 << 10

// rewriteFuzzMaxStringBytes bounds each fuzzed DNS value.
const rewriteFuzzMaxStringBytes = 512

// FuzzRewriteResponses exercises rewrite-list and settings response decoding
// with bounded structured failures.
func FuzzRewriteResponses(fuzz *testing.F) {
	fuzz.Add(uint8(0), []byte(`[]`))
	fuzz.Add(uint8(0), []byte(`[{}]`))
	fuzz.Add(uint8(0), []byte(`[{"domain":null,"answer":null,"enabled":null}]`))
	fuzz.Add(uint8(0), []byte(`[{"domain":"","answer":"","enabled":false}]`))
	fuzz.Add(uint8(0), []byte(`[{"domain":"example.test","answer":"192.0.2.2","enabled":true}]`))
	fuzz.Add(uint8(0), []byte(`[null]`))
	fuzz.Add(uint8(0), []byte(`null`))
	fuzz.Add(uint8(0), []byte(`[`))
	fuzz.Add(uint8(1), []byte(`{}`))
	fuzz.Add(uint8(1), []byte(`{"enabled":null}`))
	fuzz.Add(uint8(1), []byte(`{"enabled":false}`))
	fuzz.Add(uint8(1), []byte(`{"enabled":true,"future":true}`))
	fuzz.Add(uint8(1), []byte(`null`))
	fuzz.Add(uint8(1), []byte(`{"enabled":`))

	fuzz.Fuzz(func(t *testing.T, responseType uint8, body []byte) {
		if len(body) > rewriteFuzzMaxInputBytes {
			return
		}

		exerciseRewriteFuzzResponse(t, responseType, body)
	})
}

// FuzzRewriteRequestModels exercises rewrite rule, update, and settings request
// presence semantics and structured request errors without network access.
func FuzzRewriteRequestModels(fuzz *testing.F) {
	fuzz.Add("", "", false, false, uint8(0))
	fuzz.Add("", "", false, true, uint8(1))
	fuzz.Add("old.example", "", false, false, uint8(1))
	fuzz.Add("old.example", "192.0.2.2", true, true, uint8(2))
	fuzz.Add("new.example", "2001:db8::2", false, true, uint8(3))

	fuzz.Fuzz(func(
		t *testing.T,
		domain string,
		answer string,
		enabled bool,
		settingsEnabled bool,
		selector uint8,
	) {
		if len(domain) > rewriteFuzzMaxStringBytes || len(answer) > rewriteFuzzMaxStringBytes {
			return
		}

		rule := newAbsentRewriteFuzzRule()
		replacement := newPresentRewriteFuzzRule("replacement.example", answer, !enabled)
		if selector%2 != 0 {
			rule = newPresentRewriteFuzzRule(domain, answer, enabled)
			replacement = newAbsentRewriteFuzzRule()
		}

		update := newRewriteFuzzUpdate(rule, replacement)
		settings := RewriteSettings{Enabled: settingsEnabled}
		client := newRewriteFuzzClient(t)
		assertRewriteFuzzRequestJSON(t, rule, update, settings)
		exerciseRewriteFuzzMutations(t, client, rule, update, settings)
	})
}

// RoundTrip prevents rewrite fuzz requests from reaching an external service.
//
// Parameters:
//   - request: The request rejected by the transport.
//
// Returns:
//   - nil: No response is produced.
//   - [context.Canceled]: The deterministic transport failure.
func (rewriteFuzzTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, context.Canceled
}

// newRewriteFuzzClient creates a client whose transport cannot leave the test
// process.
//
// Parameters:
//   - tb: The fuzz or test context receiving configuration failures.
//
// Returns:
//   - client: The offline rewrite client.
func newRewriteFuzzClient(tb testing.TB) *Client {
	tb.Helper()

	client, err := NewClient(
		localTestServerURL+"/api/",
		WithHTTPClient(&http.Client{Transport: rewriteFuzzTransport{}}),
	)
	if err != nil {
		tb.Fatalf("create rewrite fuzz client: %v", err)
	}

	return client
}

// newAbsentRewriteFuzzRule creates a rewrite rule with no optional fields.
//
// Returns:
//   - rule: The fully absent rewrite rule model.
func newAbsentRewriteFuzzRule() RewriteRule {
	return RewriteRule{
		Domain:  nil,
		Answer:  nil,
		Enabled: nil,
	}
}

// newPresentRewriteFuzzRule creates a rewrite rule with every optional field.
//
// Parameters:
//   - domain: The domain value.
//   - answer: The answer value.
//   - enabled: The enabled value.
//
// Returns:
//   - rule: The fully present rewrite rule model.
func newPresentRewriteFuzzRule(domain, answer string, enabled bool) RewriteRule {
	return RewriteRule{
		Domain:  new(domain),
		Answer:  new(answer),
		Enabled: new(enabled),
	}
}

// newRewriteFuzzUpdate combines separate target and replacement rule objects.
//
// Parameters:
//   - target: The target rule object.
//   - replacement: The replacement rule object.
//
// Returns:
//   - update: The nested rewrite update model.
func newRewriteFuzzUpdate(target, replacement RewriteRule) RewriteUpdate {
	return RewriteUpdate{
		Target: target,
		Update: replacement,
	}
}

// exerciseRewriteFuzzResponse dispatches one bounded rewrite response to its
// model-specific invariant checks.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - responseType: The response-model selector supplied by the fuzzer.
//   - body: The bounded JSON response body.
func exerciseRewriteFuzzResponse(tb testing.TB, responseType uint8, body []byte) {
	tb.Helper()

	switch responseType % 2 {
	case 0:
		exerciseRewriteRulesFuzzResponse(tb, body)
	case 1:
		exerciseRewriteSettingsFuzzResponse(tb, body)
	default:
		tb.Fatalf("unreachable rewrite response selector %d", responseType%2)
	}
}

// exerciseRewriteRulesFuzzResponse checks rewrite-list decoding and metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - body: The bounded JSON response body.
func exerciseRewriteRulesFuzzResponse(tb testing.TB, body []byte) {
	tb.Helper()

	result, err := decodeRewriteRules("list_rewrite_rules", body)
	if err != nil {
		if result != nil {
			tb.Fatal("rewrite list returned rules with a JSON error")
		}

		requireRewriteFuzzError(
			tb,
			err,
			ErrorKindJSON,
			"list_rewrite_rules",
			http.MethodGet,
		)

		return
	}
	if result == nil {
		tb.Fatal("rewrite list returned a nil result without an error")
	}
}

// exerciseRewriteSettingsFuzzResponse checks settings decoding and metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - body: The bounded JSON response body.
func exerciseRewriteSettingsFuzzResponse(tb testing.TB, body []byte) {
	tb.Helper()

	result, err := decodeRewriteSettings("get_rewrite_settings", body)
	if err != nil {
		if result != nil {
			tb.Fatal("rewrite settings returned a result with a JSON error")
		}

		requireRewriteFuzzError(
			tb,
			err,
			ErrorKindJSON,
			"get_rewrite_settings",
			http.MethodGet,
		)

		return
	}
	if result == nil {
		tb.Fatal("rewrite settings returned a nil result without an error")
	}
}

// assertRewriteFuzzRequestJSON checks exact values and presence for rewrite
// rule, update, and settings request models.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - rule: The add and delete request model.
//   - update: The nested update request model.
//   - settings: The settings request model.
func assertRewriteFuzzRequestJSON(
	tb testing.TB,
	rule RewriteRule,
	update RewriteUpdate,
	settings RewriteSettings,
) {
	tb.Helper()

	wireRule := rewriteRule(rule)
	assertRewriteFuzzRule(tb, wireRule, rule)

	wireUpdate := rewriteUpdate{
		Target: rewriteRule(update.Target),
		Update: rewriteRule(update.Update),
	}
	assertRewriteFuzzUpdate(tb, wireUpdate, update)

	encoded, err := json.Marshal(rewriteSettings{Enabled: new(settings.Enabled)})
	if err != nil {
		tb.Fatalf("encode rewrite settings request: %v", err)
	}
	var fields map[string]any

	err = json.Unmarshal(encoded, &fields)
	if err != nil {
		tb.Fatalf("decode rewrite settings request: %v", err)
	}
	if len(fields) != 1 {
		tb.Fatalf("rewrite settings has %d keys, want 1: %s", len(fields), encoded)
	}

	encodedEnabled, ok := fields["enabled"].(bool)
	if !ok || encodedEnabled != settings.Enabled {
		tb.Fatalf("rewrite settings enabled = %#v, want %t", fields["enabled"], settings.Enabled)
	}
}

// assertRewriteFuzzUpdate checks the nested target and replacement objects in
// one rewrite update payload.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - payload: The encoded update model under test.
//   - update: The expected target and replacement values.
func assertRewriteFuzzUpdate(tb testing.TB, payload rewriteUpdate, update RewriteUpdate) {
	tb.Helper()

	encoded, err := json.Marshal(payload)
	if err != nil {
		if _, ok := errors.AsType[*jsontext.SyntacticError](err); !ok {
			tb.Fatalf("encode rewrite update request: %T %v", err, err)
		}

		return
	}
	var fields map[string]map[string]any

	err = json.Unmarshal(encoded, &fields)
	if err != nil {
		tb.Fatalf("decode rewrite update request: %v", err)
	}
	if len(fields) != 2 {
		tb.Fatalf("rewrite update has %d keys, want 2: %s", len(fields), encoded)
	}

	assertRewriteFuzzRuleFields(tb, fields["target"], update.Target)
	assertRewriteFuzzRuleFields(tb, fields["update"], update.Update)
}

// assertRewriteFuzzRule checks one encoded rewrite rule payload.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - payload: The encoded rule model under test.
//   - rule: The expected rule values.
func assertRewriteFuzzRule(tb testing.TB, payload rewriteRule, rule RewriteRule) {
	tb.Helper()

	encoded, err := json.Marshal(payload)
	if err != nil {
		if _, ok := errors.AsType[*jsontext.SyntacticError](err); !ok {
			tb.Fatalf("encode rewrite rule request: %T %v", err, err)
		}

		return
	}
	var fields map[string]any

	err = json.Unmarshal(encoded, &fields)
	if err != nil {
		tb.Fatalf("decode rewrite rule request: %v", err)
	}

	assertRewriteFuzzRuleFields(tb, fields, rule)
}

// assertRewriteFuzzRuleFields checks the exact values and presence of one
// decoded rewrite rule object.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - fields: The decoded rule object.
//   - rule: The expected rule values.
func assertRewriteFuzzRuleFields(tb testing.TB, fields map[string]any, rule RewriteRule) {
	tb.Helper()

	expectedCount := rewriteFuzzRuleFieldCount(rule)
	if len(fields) != expectedCount {
		tb.Fatalf("rewrite rule has %d fields, want %d: %#v", len(fields), expectedCount, fields)
	}

	assertRewriteFuzzStringField(tb, fields, "domain", rule.Domain)
	assertRewriteFuzzStringField(tb, fields, "answer", rule.Answer)
	assertRewriteFuzzBoolField(tb, fields, "enabled", rule.Enabled)
}

// rewriteFuzzRuleFieldCount returns the number of fields emitted for one rule.
//
// Parameters:
//   - rule: The expected rewrite rule values.
//
// Returns:
//   - count: The expected encoded field count.
func rewriteFuzzRuleFieldCount(rule RewriteRule) int {
	count := 0

	for _, present := range []bool{
		rule.Domain != nil && *rule.Domain != "",
		rule.Answer != nil && *rule.Answer != "",
		rule.Enabled != nil,
	} {
		if present {
			count++
		}
	}

	return count
}

// assertRewriteFuzzStringField checks one optional encoded rewrite string.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - fields: The decoded rule object.
//   - key: The JSON field name.
//   - expected: The optional expected string value.
func assertRewriteFuzzStringField(
	tb testing.TB,
	fields map[string]any,
	key string,
	expected *string,
) {
	tb.Helper()

	if expected != nil && *expected != "" {
		value, ok := fields[key].(string)
		if !ok || value != *expected {
			tb.Fatalf("rewrite rule %s = %#v, want %q", key, fields[key], *expected)
		}

		return
	}
	if _, present := fields[key]; present {
		tb.Fatalf("rewrite rule unexpectedly contains %s: %#v", key, fields)
	}
}

// assertRewriteFuzzBoolField checks one optional encoded rewrite boolean.
//
// Parameters:
//   - tb: The fuzz context receiving serialization failures.
//   - fields: The decoded rule object.
//   - key: The JSON field name.
//   - expected: The optional expected boolean value.
func assertRewriteFuzzBoolField(
	tb testing.TB,
	fields map[string]any,
	key string,
	expected *bool,
) {
	tb.Helper()

	if expected == nil {
		if _, present := fields[key]; present {
			tb.Fatalf("rewrite rule unexpectedly contains %s: %#v", key, fields)
		}

		return
	}

	value, ok := fields[key].(bool)
	if !ok || value != *expected {
		tb.Fatalf("rewrite rule %s = %#v, want %t", key, fields[key], *expected)
	}
}

// exerciseRewriteFuzzMutations sends every rewrite mutation through the
// rejecting in-memory transport and checks its structured request error.
//
// Parameters:
//   - t: The fuzz context receiving request failures.
//   - client: The offline rewrite client.
//   - rule: The add and delete request model.
//   - update: The update request model.
//   - settings: The settings request model.
func exerciseRewriteFuzzMutations(
	t *testing.T,
	client *Client,
	rule RewriteRule,
	update RewriteUpdate,
	settings RewriteSettings,
) {
	t.Helper()

	ctx := t.Context()
	operations := []struct {
		operation string
		method    string
		call      func() error
	}{
		{operation: "add_rewrite_rule", method: http.MethodPost, call: func() error {
			return client.AddRewriteRule(ctx, rule)
		}},
		{operation: "delete_rewrite_rule", method: http.MethodPost, call: func() error {
			return client.DeleteRewriteRule(ctx, rule)
		}},
		{operation: "update_rewrite_rule", method: http.MethodPut, call: func() error {
			return client.UpdateRewriteRule(ctx, update)
		}},
		{operation: "update_rewrite_settings", method: http.MethodPut, call: func() error {
			return client.UpdateRewriteSettings(ctx, settings)
		}},
	}

	for _, operation := range operations {
		err := operation.call()
		if errors.Is(err, errEncodeRewriteRequest) {
			requireRewriteFuzzError(
				t,
				err,
				ErrorKindJSON,
				operation.operation,
				operation.method,
			)

			continue
		}

		requireRewriteFuzzError(
			t,
			err,
			ErrorKindRequest,
			operation.operation,
			operation.method,
		)

		if !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"%s error does not preserve the transport cause: %v",
				operation.operation,
				err,
			)
		}
	}
}

// requireRewriteFuzzError verifies that a rewrite error has the required
// structured classification and metadata.
//
// Parameters:
//   - tb: The fuzz context receiving invariant failures.
//   - err: The error to inspect.
//   - kind: The expected structured error kind.
//   - operation: The expected operation name.
//   - method: The expected HTTP method.
func requireRewriteFuzzError(
	tb testing.TB,
	err error,
	kind ErrorKind,
	operation string,
	method string,
) {
	tb.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	if !ok || clientErr == nil {
		tb.Fatalf("rewrite error is not structured: %T %v", err, err)
	}
	if clientErr.Kind != kind || clientErr.Operation != operation || clientErr.Method != method {
		tb.Fatalf(
			"rewrite error metadata = (%q, %q, %q), want (%q, %q, %q)",
			clientErr.Kind,
			clientErr.Operation,
			clientErr.Method,
			kind,
			operation,
			method,
		)
	}
	if clientErr.Err == nil {
		tb.Fatalf("structured rewrite error %q has no cause", operation)
	}
}
