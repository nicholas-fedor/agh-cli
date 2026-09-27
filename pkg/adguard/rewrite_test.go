// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// The answer is a stable test DNS answer.
	rewriteTestAnswer = "192.0.2.2"
)

// TestListRewriteRequest verifies the list method, path, and response contract.
func TestListRewriteRequest(t *testing.T) {
	t.Parallel()

	assertRewriteRequest(
		t,
		http.MethodGet,
		"/api/control/rewrite/list",
		"",
		jsonContentType+"; charset=utf-8",
		`[]`,
		func(client *Client) error {
			_, err := client.ListRewriteRules(t.Context())

			return err
		},
	)
}

// TestAddRewriteRequest verifies the add method, path, payload, and empty success.
func TestAddRewriteRequest(t *testing.T) {
	t.Parallel()

	rule := newRewriteRuleFixture(false)

	assertRewriteRequest(
		t,
		http.MethodPost,
		"/api/control/rewrite/add",
		`{"domain":"old.example","answer":"192.0.2.2","enabled":false}`,
		"",
		"",
		func(client *Client) error {
			return client.AddRewriteRule(t.Context(), rule)
		},
	)
}

// TestDeleteRewriteRequest verifies the delete method, path, payload, and empty success.
func TestDeleteRewriteRequest(t *testing.T) {
	t.Parallel()

	rule := newRewriteRuleFixture(false)

	assertRewriteRequest(
		t,
		http.MethodPost,
		"/api/control/rewrite/delete",
		`{"domain":"old.example","answer":"192.0.2.2","enabled":false}`,
		"",
		"",
		func(client *Client) error {
			return client.DeleteRewriteRule(t.Context(), rule)
		},
	)
}

// TestUpdateRewriteRequest verifies separate target and replacement values.
func TestUpdateRewriteRequest(t *testing.T) {
	t.Parallel()

	assertRewriteRequest(
		t,
		http.MethodPut,
		"/api/control/rewrite/update",
		`{
			"target":{"domain":"old.example","answer":"192.0.2.2","enabled":false},
			"update":{"domain":"new.example","answer":"192.0.2.2","enabled":true}
		}`,
		"",
		"",
		func(client *Client) error {
			return client.UpdateRewriteRule(t.Context(), RewriteUpdate{
				Target: newRewriteRuleFixture(false),
				Update: newRewriteReplacementFixture(),
			})
		},
	)
}

// TestGetRewriteSettingsRequest verifies the settings method, path, and response contract.
func TestGetRewriteSettingsRequest(t *testing.T) {
	t.Parallel()

	assertRewriteRequest(
		t,
		http.MethodGet,
		"/api/control/rewrite/settings",
		"",
		jsonContentType,
		`{"enabled":true}`,
		func(client *Client) error {
			_, err := client.GetRewriteSettings(t.Context())

			return err
		},
	)
}

// TestUpdateRewriteSettingsRequest verifies explicit false serialization and empty success.
func TestUpdateRewriteSettingsRequest(t *testing.T) {
	t.Parallel()

	assertRewriteRequest(
		t,
		http.MethodPut,
		"/api/control/rewrite/settings/update",
		`{"enabled":false}`,
		"",
		"",
		func(client *Client) error {
			return client.UpdateRewriteSettings(t.Context(), RewriteSettings{Enabled: false})
		},
	)
}

// assertRewriteRequest verifies shared request metadata and invokes one rewrite operation.
//
// Parameters:
//   - method: The expected HTTP method.
//   - path: The expected API path.
//   - requestBody: The expected JSON request body, or an empty string for no body.
//   - responseType: The response Content-Type, or an empty string to omit it.
//   - responseBody: The response body returned by the test server.
//   - invoke: The rewrite operation to execute.
func assertRewriteRequest(
	t *testing.T,
	method string,
	path string,
	requestBody string,
	responseType string,
	responseBody string,
	invoke func(*Client) error,
) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "test-user", username)
		assert.Equal(t, "test-password", password)
		assert.Equal(t, method, r.Method)
		assert.Equal(t, path, r.URL.Path)
		assert.Empty(t, r.URL.RawQuery)
		assert.Equal(t, []string{jsonContentType}, r.Header.Values("Accept"))
		assert.Equal(t, "adguard-client-test/1.0", r.Header.Get("User-Agent"))

		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		if err != nil {
			return
		}
		if requestBody == "" {
			assert.Empty(t, body)
			assert.Empty(t, r.Header.Get("Content-Type"))
		} else {
			assert.JSONEq(t, requestBody, string(body))
			assert.Equal(t, []string{jsonContentType}, r.Header.Values("Content-Type"))
		}

		if responseType != "" {
			w.Header().Set("Content-Type", responseType)
		}

		writeBody(w, responseBody)
	}))
	client := newRewriteTestClient(t, server, "/api/", 1024)

	err := invoke(client)

	require.NoError(t, err)
}

// TestListRewriteRules verifies optional entry presence and unknown fields.
func TestListRewriteRules(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", jsonContentType)
		writeBody(w, `[
			{"domain":"false.example","answer":"192.0.2.2","enabled":false},
			{"domain":"absent.example","answer":"192.0.2.2"},
			{"domain":null,"answer":null,"enabled":null,"future":true}
		]`)
	}))
	client := newRewriteTestClient(t, server, "", 1024)

	rules, err := client.ListRewriteRules(t.Context())

	require.NoError(t, err)
	require.Len(t, rules, 3)
	require.NotNil(t, rules[0].Domain)
	assert.Equal(t, "false.example", *rules[0].Domain)
	require.NotNil(t, rules[0].Answer)
	assert.Equal(t, rewriteTestAnswer, *rules[0].Answer)
	require.NotNil(t, rules[0].Enabled)
	assert.False(t, *rules[0].Enabled)
	assert.Nil(t, rules[1].Enabled)
	assert.Nil(t, rules[2].Domain)
	assert.Nil(t, rules[2].Answer)
	assert.Nil(t, rules[2].Enabled)
}

// TestGetRewriteSettings verifies the required enabled field.
func TestGetRewriteSettings(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", jsonContentType)
		writeBody(w, `{"enabled":false,"future":true}`)
	}))
	client := newRewriteTestClient(t, server, "", 1024)

	settings, err := client.GetRewriteSettings(t.Context())

	require.NoError(t, err)
	assert.False(t, settings.Enabled)
}

// TestRewriteRuleEnabledRequestPresence verifies omission and explicit boolean serialization.
func TestRewriteRuleEnabledRequestPresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		enabled *bool
		body    string
	}{
		{
			name:    safetyAbsentName,
			enabled: nil,
			body:    `{"domain":"example.org","answer":"192.0.2.2"}`,
		},
		{
			name:    "disabled",
			enabled: new(false),
			body:    `{"domain":"example.org","answer":"192.0.2.2","enabled":false}`,
		},
		{
			name:    safetyEnabledKey,
			enabled: new(true),
			body:    `{"domain":"example.org","answer":"192.0.2.2","enabled":true}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertRewriteEnabledRequest(t, test.body, test.enabled)
		})
	}
}

// assertRewriteEnabledRequest verifies one optional enabled serialization case.
//
// Parameters:
//   - expectedBody: The expected JSON request body.
//   - enabled: The optional enabled pointer to encode.
func assertRewriteEnabledRequest(t *testing.T, expectedBody string, enabled *bool) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		assert.NoError(t, err)

		if err != nil {
			return
		}

		assert.JSONEq(t, expectedBody, string(body))
	}))
	client := newRewriteTestClient(t, server, "", 1024)

	err := client.AddRewriteRule(t.Context(), RewriteRule{
		Domain:  new("example.org"),
		Answer:  new(rewriteTestAnswer),
		Enabled: enabled,
	})

	require.NoError(t, err)
}

// TestRewriteReadRejectsInvalidJSON verifies response decoding failures.
func TestRewriteReadRejectsInvalidJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		invoke func(*testing.T, *Client) error
	}{
		{
			name: "malformed list",
			body: `[`,
			invoke: func(t *testing.T, client *Client) error {
				t.Helper()

				_, err := client.ListRewriteRules(t.Context())

				return err
			},
		},
		{
			name: "null list",
			body: testNullJSON,
			invoke: func(t *testing.T, client *Client) error {
				t.Helper()

				_, err := client.ListRewriteRules(t.Context())

				return err
			},
		},
		{
			name: "null list entry",
			body: `[null]`,
			invoke: func(t *testing.T, client *Client) error {
				t.Helper()

				_, err := client.ListRewriteRules(t.Context())

				return err
			},
		},
		{
			name: "missing settings enabled",
			body: `{}`,
			invoke: func(t *testing.T, client *Client) error {
				t.Helper()

				_, err := client.GetRewriteSettings(t.Context())

				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", jsonContentType)
				writeBody(w, test.body)
			}))
			client := newRewriteTestClient(t, server, "", 1024)

			err := test.invoke(t, client)

			clientErr := requireClientError(t, err, ErrorKindJSON)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestRewriteReadRejectsWrongContentType verifies JSON media type enforcement.
func TestRewriteReadRejectsWrongContentType(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		writeBody(w, `[]`)
	}))
	client := newRewriteTestClient(t, server, "", 1024)

	_, err := client.ListRewriteRules(t.Context())

	clientErr := requireClientError(t, err, ErrorKindContentType)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, "text/plain", clientErr.ContentType)
}

// TestRewriteMutationsRejectNonSuccessStatus verifies mutation status errors and methods.
func TestRewriteMutationsRejectNonSuccessStatus(t *testing.T) {
	t.Parallel()

	domain := filteringHostName
	tests := []struct {
		name       string
		method     string
		invoke     func(*testing.T, *Client) error
		statusCode int
	}{
		{
			name:       clientsAddTestName,
			method:     http.MethodPost,
			statusCode: http.StatusUnauthorized,
			invoke: func(t *testing.T, client *Client) error {
				t.Helper()

				return client.AddRewriteRule(t.Context(), RewriteRule{
					Domain:  &domain,
					Answer:  nil,
					Enabled: nil,
				})
			},
		},
		{
			name:       "update settings",
			method:     http.MethodPut,
			statusCode: http.StatusTeapot,
			invoke: func(t *testing.T, client *Client) error {
				t.Helper()

				return client.UpdateRewriteSettings(t.Context(), RewriteSettings{Enabled: true})
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(test.statusCode)
				writeBody(w, "failed")
			}))
			client := newRewriteTestClient(t, server, "", 1024)

			err := test.invoke(t, client)

			clientErr := requireClientError(t, err, ErrorKindStatus)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.statusCode, clientErr.StatusCode)
			assert.Equal(t, "failed", string(clientErr.Body))
		})
	}
}

// TestListRewriteRulesRejectsOversizedBody verifies the configured response limit.
func TestListRewriteRulesRejectsOversizedBody(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", jsonContentType)
		writeBody(w, `[]`)
	}))
	client := newRewriteTestClient(t, server, "", 1)

	_, err := client.ListRewriteRules(t.Context())

	clientErr := requireClientError(t, err, ErrorKindResponseTooLarge)
	assert.Equal(t, http.MethodGet, clientErr.Method)
	assert.Equal(t, int64(1), clientErr.Limit)
}

// TestAddRewriteRuleHonorsCancellation verifies context cancellation propagation.
func TestAddRewriteRuleHonorsCancellation(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	client := newRewriteTestClient(t, server, "", 1024)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	err := client.AddRewriteRule(ctx, RewriteRule{
		Domain:  nil,
		Answer:  nil,
		Enabled: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestAddRewriteRuleHonorsRequestTimeout verifies per-request deadlines.
func TestAddRewriteRuleHonorsRequestTimeout(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
	}))
	client := newRewriteTestClient(t, server, "", 1024, WithRequestTimeout(20*time.Millisecond))

	err := client.AddRewriteRule(t.Context(), RewriteRule{
		Domain:  nil,
		Answer:  nil,
		Enabled: nil,
	})

	clientErr := requireClientError(t, err, ErrorKindRequest)
	assert.Equal(t, http.MethodPost, clientErr.Method)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// newRewriteTestClient creates a rewrite client bound to an in-memory server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//   - basePath: The API base path appended to the local server URL.
//   - limit: The maximum response body size in bytes.
//   - options: Additional client options for the test.
//
// Returns:
//   - client: The configured AdGuard client.
func newRewriteTestClient(
	t *testing.T,
	server *httptest.Server,
	basePath string,
	limit int64,
	options ...Option,
) *Client {
	t.Helper()

	appendOptions := make([]Option, 0, 4+len(options))

	appendOptions = append(
		appendOptions,
		WithHTTPClient(server.Client()),
		WithBasicAuth("test-user", "test-password"),
		WithUserAgent("adguard-client-test/1.0"),
		WithMaxResponseBodySize(limit),
	)
	appendOptions = append(appendOptions, options...)

	client, err := NewClient(localTestServerURL+basePath, appendOptions...)
	require.NoError(t, err)

	return client
}

// newRewriteRuleFixture returns the target rule used by request contract tests.
//
// Parameters:
//   - enabled: The enabled state placed in the fixture.
//
// Returns:
//   - rule: The configured target rewrite rule.
func newRewriteRuleFixture(enabled bool) RewriteRule {
	return RewriteRule{
		Domain:  new("old.example"),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(enabled),
	}
}

// newRewriteReplacementFixture returns the replacement rule used by update contract tests.
//
// Returns:
//   - rule: The configured replacement rewrite rule.
func newRewriteReplacementFixture() RewriteRule {
	return RewriteRule{
		Domain:  new("new.example"),
		Answer:  new("192.0.2.2"),
		Enabled: new(true),
	}
}
