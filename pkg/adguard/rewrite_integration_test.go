// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// rewriteIntegrationCall invokes one rewrite operation.
type rewriteIntegrationCall func(context.Context, *adguard.Client) error

// rewriteIntegrationRequestContract describes one successful rewrite request.
type rewriteIntegrationRequestContract struct {
	call                rewriteIntegrationCall
	method              string
	name                string
	path                string
	requestBody         string
	responseBody        string
	responseContentType string
	status              int
	verify              func(*testing.T)
}

// rewriteIntegrationRequestCapture contains one captured rewrite request.
type rewriteIntegrationRequestCapture struct {
	accept      []string
	body        []byte
	closeErr    error
	contentType []string
	hasAuth     bool
	method      string
	path        string
	query       string
	readErr     error
	userAgent   string
	username    string
	password    string
}

// rewriteIntegrationStatusErrorContract describes one rewrite status-error case.
type rewriteIntegrationStatusErrorContract struct {
	call      rewriteIntegrationCall
	method    string
	name      string
	operation string
	path      string
}

// rewriteIntegrationResponseErrorContract describes one rewrite response-error case.
type rewriteIntegrationResponseErrorContract struct {
	call            rewriteIntegrationCall
	contentType     string
	method          string
	name            string
	operation       string
	responseBody    string
	wantKind        adguard.ErrorKind
	wantContentType string
}

const (
	// The expected HTTP Basic username.
	rewriteIntegrationUsername = "rewrite-integration-user"
	// The expected HTTP Basic password.
	rewriteIntegrationPassword = "rewrite-integration-password"
	// The expected client User-Agent.
	rewriteIntegrationUserAgent = "rewrite-integration-client/1.0"
	// The list rewrite operation identifier.
	rewriteIntegrationListOperation = "list_rewrite_rules"
	// The add-rule test case name.
	rewriteIntegrationAddName = "add"
	// The structured status-error payload.
	rewriteIntegrationStatusErrorBody = `{"message":"rewrite rejected"}`
	// The expected HTTP status line.
	rewriteIntegrationStatusErrorMessage = "422 Unprocessable Entity"
)

// TestClientRewriteIntegrationRequestContract verifies every rewrite operation's HTTP contract.
func TestClientRewriteIntegrationRequestContract(t *testing.T) {
	t.Parallel()

	contracts := slices.Concat(
		rewriteIntegrationRuleContracts(),
		rewriteIntegrationSettingsContracts(),
	)

	for _, contract := range contracts {
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()

			runRewriteIntegrationRequestContract(t, contract)
		})
	}
}

// TestClientRewriteIntegrationStatusErrors verifies structured status errors for every rewrite operation.
func TestClientRewriteIntegrationStatusErrors(t *testing.T) {
	t.Parallel()

	for _, contract := range rewriteIntegrationStatusErrorContracts() {
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()

			runRewriteIntegrationStatusErrorContract(t, contract)
		})
	}
}

// TestClientRewriteIntegrationResponseErrors verifies structured response-decoding errors.
func TestClientRewriteIntegrationResponseErrors(t *testing.T) {
	t.Parallel()

	for _, contract := range rewriteIntegrationResponseErrorContracts() {
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()

			runRewriteIntegrationResponseErrorContract(t, contract)
		})
	}
}

// rewriteIntegrationResponseErrorContracts returns rewrite response-error cases.
//
// Returns:
//   - contracts: The list and settings response-error contracts.
func rewriteIntegrationResponseErrorContracts() []rewriteIntegrationResponseErrorContract {
	listCall := func(ctx context.Context, client *adguard.Client) error {
		_, err := client.ListRewriteRules(ctx)

		return err
	}
	settingsCall := func(ctx context.Context, client *adguard.Client) error {
		_, err := client.GetRewriteSettings(ctx)

		return err
	}

	return []rewriteIntegrationResponseErrorContract{
		{
			call:         listCall,
			contentType:  blockedServicesIntegrationJSONContentType,
			method:       http.MethodGet,
			name:         "malformed list",
			operation:    rewriteIntegrationListOperation,
			responseBody: `[`,
			wantKind:     adguard.ErrorKindJSON,
		},
		{
			call:         listCall,
			contentType:  blockedServicesIntegrationJSONContentType,
			method:       http.MethodGet,
			name:         "null list",
			operation:    rewriteIntegrationListOperation,
			responseBody: safetyIntegrationNullName,
			wantKind:     adguard.ErrorKindJSON,
		},
		{
			call:         settingsCall,
			contentType:  blockedServicesIntegrationJSONContentType,
			method:       http.MethodGet,
			name:         "missing settings enabled",
			operation:    "get_rewrite_settings",
			responseBody: `{}`,
			wantKind:     adguard.ErrorKindJSON,
		},
		{
			call:            listCall,
			contentType:     filteringIntegrationTextMediaType,
			method:          http.MethodGet,
			name:            "wrong list media type",
			operation:       rewriteIntegrationListOperation,
			responseBody:    `[]`,
			wantKind:        adguard.ErrorKindContentType,
			wantContentType: filteringIntegrationTextMediaType,
		},
	}
}

// runRewriteIntegrationResponseErrorContract verifies one structured rewrite response error.
//
// Parameters:
//   - contract: The rewrite response-error contract to exercise.
func runRewriteIntegrationResponseErrorContract(
	t *testing.T,
	contract rewriteIntegrationResponseErrorContract,
) {
	t.Helper()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeRewriteIntegrationResponse(w, contract.contentType, http.StatusOK, contract.responseBody)
	}))
	client := newRewriteIntegrationClient(t, server)

	err := contract.call(t.Context(), client)

	clientErr := requireRewriteIntegrationError(t, err, contract.wantKind)
	assert.Equal(t, contract.operation, clientErr.Operation)
	assert.Equal(t, contract.method, clientErr.Method)
	assert.Equal(t, contract.wantContentType, clientErr.ContentType)
}

// rewriteIntegrationRuleContracts returns the rewrite-rule request contracts.
//
// Returns:
//   - contracts: The list, add, delete, and update rule contracts.
func rewriteIntegrationRuleContracts() []rewriteIntegrationRequestContract {
	return slices.Concat(
		rewriteIntegrationListContract(),
		rewriteIntegrationAddDeleteContracts(),
		rewriteIntegrationUpdateContract(),
	)
}

// rewriteIntegrationListContract returns the list request contract.
//
// Returns:
//   - contracts: The list request contract and its response assertion.
func rewriteIntegrationListContract() []rewriteIntegrationRequestContract {
	expectedRules := []adguard.RewriteRule{
		{
			Domain:  new("source.example"),
			Answer:  new("192.0.2.10"),
			Enabled: new(false),
		},
		{
			Domain: new("alias.example"),
		},
	}
	var listedRules []adguard.RewriteRule

	return []rewriteIntegrationRequestContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				var err error

				listedRules, err = client.ListRewriteRules(ctx)

				return err
			},
			method:      http.MethodGet,
			name:        "list",
			path:        "/api/control/rewrite/list",
			requestBody: "",
			responseBody: `[{"domain":"source.example","answer":"192.0.2.10","enabled":false},` +
				`{"domain":"alias.example"}]`,
			responseContentType: blockedServicesIntegrationJSONContentType + "; charset=utf-8",
			status:              http.StatusOK,
			verify: func(t *testing.T) {
				t.Helper()

				assert.Equal(t, expectedRules, listedRules)
			},
		},
	}
}

// rewriteIntegrationAddDeleteContracts returns the add and delete request contracts.
//
// Returns:
//   - contracts: The add and delete request contracts.
func rewriteIntegrationAddDeleteContracts() []rewriteIntegrationRequestContract {
	return []rewriteIntegrationRequestContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.AddRewriteRule(ctx, adguard.RewriteRule{
					Domain:  new("source.example"),
					Answer:  new("192.0.2.10"),
					Enabled: new(false),
				})
			},
			method:              http.MethodPost,
			name:                rewriteIntegrationAddName,
			path:                "/api/control/rewrite/add",
			requestBody:         `{"domain":"source.example","answer":"192.0.2.10","enabled":false}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
			verify:              nil,
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DeleteRewriteRule(ctx, adguard.RewriteRule{
					Domain:  new("obsolete.example"),
					Answer:  nil,
					Enabled: new(false),
				})
			},
			method:              http.MethodPost,
			name:                "delete",
			path:                "/api/control/rewrite/delete",
			requestBody:         `{"domain":"obsolete.example","enabled":false}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
			verify:              nil,
		},
	}
}

// rewriteIntegrationUpdateContract returns the target and replacement update contract.
//
// Returns:
//   - contracts: The rule update request contract.
func rewriteIntegrationUpdateContract() []rewriteIntegrationRequestContract {
	return []rewriteIntegrationRequestContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateRewriteRule(ctx, adguard.RewriteUpdate{
					Target: adguard.RewriteRule{
						Domain:  new("old.example"),
						Answer:  new("192.0.2.10"),
						Enabled: new(false),
					},
					Update: adguard.RewriteRule{
						Domain:  new("new.example"),
						Answer:  new("2001:db8::10"),
						Enabled: new(true),
					},
				})
			},
			method: http.MethodPut,
			name:   "update",
			path:   "/api/control/rewrite/update",
			requestBody: `{"target":{"domain":"old.example","answer":"192.0.2.10","enabled":false},` +
				`"update":{"domain":"new.example","answer":"2001:db8::10","enabled":true}}`,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
			verify:              nil,
		},
	}
}

// rewriteIntegrationSettingsContracts returns the rewrite-settings request contracts.
//
// Returns:
//   - contracts: The settings read and update contracts.
func rewriteIntegrationSettingsContracts() []rewriteIntegrationRequestContract {
	var settings *adguard.RewriteSettings

	return []rewriteIntegrationRequestContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				var err error

				settings, err = client.GetRewriteSettings(ctx)

				return err
			},
			method:              http.MethodGet,
			name:                "get settings",
			path:                "/api/control/rewrite/settings",
			requestBody:         "",
			responseBody:        integrationEnabledFalseJSON,
			responseContentType: blockedServicesIntegrationJSONContentType,
			status:              http.StatusOK,
			verify: func(t *testing.T) {
				t.Helper()

				require.NotNil(t, settings)
				assert.False(t, settings.Enabled)
			},
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateRewriteSettings(ctx, adguard.RewriteSettings{Enabled: false})
			},
			method:              http.MethodPut,
			name:                "update settings",
			path:                "/api/control/rewrite/settings/update",
			requestBody:         integrationEnabledFalseJSON,
			responseBody:        "",
			responseContentType: "",
			status:              http.StatusNoContent,
			verify:              nil,
		},
	}
}

// rewriteIntegrationStatusErrorContracts returns status-error contracts for every operation.
//
// Returns:
//   - contracts: The six rewrite operation status-error contracts.
func rewriteIntegrationStatusErrorContracts() []rewriteIntegrationStatusErrorContract {
	return []rewriteIntegrationStatusErrorContract{
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.ListRewriteRules(ctx)

				return err
			},
			method:    http.MethodGet,
			name:      "list",
			operation: rewriteIntegrationListOperation,
			path:      "/api/control/rewrite/list",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.AddRewriteRule(ctx, adguard.RewriteRule{})
			},
			method:    http.MethodPost,
			name:      rewriteIntegrationAddName,
			operation: "add_rewrite_rule",
			path:      "/api/control/rewrite/add",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.DeleteRewriteRule(ctx, adguard.RewriteRule{})
			},
			method:    http.MethodPost,
			name:      "delete",
			operation: "delete_rewrite_rule",
			path:      "/api/control/rewrite/delete",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateRewriteRule(ctx, adguard.RewriteUpdate{})
			},
			method:    http.MethodPut,
			name:      blockedServicesIntegrationUpdateName,
			operation: "update_rewrite_rule",
			path:      "/api/control/rewrite/update",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetRewriteSettings(ctx)

				return err
			},
			method:    http.MethodGet,
			name:      "get settings",
			operation: "get_rewrite_settings",
			path:      "/api/control/rewrite/settings",
		},
		{
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateRewriteSettings(ctx, adguard.RewriteSettings{})
			},
			method:    http.MethodPut,
			name:      "update settings",
			operation: "update_rewrite_settings",
			path:      "/api/control/rewrite/settings/update",
		},
	}
}

// runRewriteIntegrationRequestContract verifies one successful rewrite request contract.
//
// Parameters:
//   - contract: The rewrite request contract to exercise.
func runRewriteIntegrationRequestContract(t *testing.T, contract rewriteIntegrationRequestContract) {
	t.Helper()

	captured := make(chan rewriteIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureRewriteIntegrationRequest(r)

		writeRewriteIntegrationResponse(
			w,
			contract.responseContentType,
			contract.status,
			contract.responseBody,
		)
	}))
	client := newRewriteIntegrationClient(t, server)

	err := contract.call(t.Context(), client)

	require.NoError(t, err)

	request := <-captured
	assertRewriteIntegrationRequest(t, contract, request)

	if contract.verify != nil {
		contract.verify(t)
	}
}

// runRewriteIntegrationStatusErrorContract verifies one rewrite operation's structured status error.
//
// Parameters:
//   - contract: The rewrite status-error contract to exercise.
func runRewriteIntegrationStatusErrorContract(
	t *testing.T,
	contract rewriteIntegrationStatusErrorContract,
) {
	t.Helper()

	captured := make(chan rewriteIntegrationRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured <- captureRewriteIntegrationRequest(r)

		writeRewriteIntegrationResponse(
			w,
			blockedServicesIntegrationProblemContentType,
			http.StatusUnprocessableEntity,
			rewriteIntegrationStatusErrorBody,
		)
	}))
	client := newRewriteIntegrationClient(t, server)

	err := contract.call(t.Context(), client)

	clientErr := requireRewriteIntegrationError(t, err, adguard.ErrorKindStatus)
	assert.Equal(t, contract.operation, clientErr.Operation)
	assert.Equal(t, contract.method, clientErr.Method)
	assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
	assert.Equal(t, rewriteIntegrationStatusErrorMessage, clientErr.Status)
	assert.Equal(t, blockedServicesIntegrationProblemContentType, clientErr.ContentType)
	assert.JSONEq(t, rewriteIntegrationStatusErrorBody, string(clientErr.Body))
	require.NoError(t, clientErr.Err)

	request := <-captured
	assert.Equal(t, contract.method, request.method)
	assert.Equal(t, contract.path, request.path)
	assertRewriteIntegrationAuthentication(t, request)
}

// writeRewriteIntegrationResponse writes one rewrite integration test response.
//
// Parameters:
//   - w: The response writer receiving the response.
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP status code.
//   - body: The response body.
func writeRewriteIntegrationResponse(
	w http.ResponseWriter,
	contentType string,
	status int,
	body string,
) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(status)

	if body == "" {
		return
	}

	_, err := io.WriteString(w, body)
	if err != nil {
		return
	}
}

// captureRewriteIntegrationRequest captures one rewrite request and consumes its body.
//
// Parameters:
//   - request: The HTTP request captured by the test server.
//
// Returns:
//   - capture: The captured request metadata and body errors.
func captureRewriteIntegrationRequest(request *http.Request) rewriteIntegrationRequestCapture {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	username, password, hasAuth := request.BasicAuth()

	return rewriteIntegrationRequestCapture{
		accept:      request.Header.Values("Accept"),
		body:        body,
		closeErr:    closeErr,
		contentType: request.Header.Values("Content-Type"),
		hasAuth:     hasAuth,
		method:      request.Method,
		path:        request.URL.Path,
		query:       request.URL.RawQuery,
		readErr:     readErr,
		userAgent:   request.Header.Get("User-Agent"),
		username:    username,
		password:    password,
	}
}

// assertRewriteIntegrationRequest verifies one captured request against its contract.
//
// Parameters:
//   - contract: The expected request contract.
//   - request: The captured request metadata.
func assertRewriteIntegrationRequest(
	t *testing.T,
	contract rewriteIntegrationRequestContract,
	request rewriteIntegrationRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, contract.method, request.method)
	assert.Equal(t, contract.path, request.path)
	assert.Empty(t, request.query)
	assert.Equal(t, []string{blockedServicesIntegrationJSONContentType}, request.accept)
	assert.Equal(t, rewriteIntegrationUserAgent, request.userAgent)
	assertRewriteIntegrationAuthentication(t, request)

	if contract.method == http.MethodGet {
		assert.Empty(t, request.body)
		assert.Empty(t, request.contentType)
	} else {
		assert.Equal(t, []string{blockedServicesIntegrationJSONContentType}, request.contentType)
		assert.Equal(t, contract.requestBody, string(request.body))
	}
}

// assertRewriteIntegrationAuthentication verifies exact HTTP Basic credentials.
//
// Parameters:
//   - request: The captured request metadata.
func assertRewriteIntegrationAuthentication(t *testing.T, request rewriteIntegrationRequestCapture) {
	t.Helper()

	assert.True(t, request.hasAuth)
	assert.Equal(t, rewriteIntegrationUsername, request.username)
	assert.Equal(t, rewriteIntegrationPassword, request.password)
}

// requireRewriteIntegrationError extracts and verifies a structured rewrite error.
//
// Parameters:
//   - err: The error to inspect.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted structured client error.
func requireRewriteIntegrationError(
	t *testing.T,
	err error,
	kind adguard.ErrorKind,
) *adguard.Error {
	t.Helper()

	clientErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}

// newRewriteIntegrationClient creates a concrete client bound to a rewrite integration server.
//
// Parameters:
//   - server: The HTTP test server supplying the transport.
//
// Returns:
//   - client: The configured AdGuard client.
func newRewriteIntegrationClient(t *testing.T, server *httptest.Server) *adguard.Client {
	t.Helper()

	client, err := adguard.NewClient(
		blockedServicesIntegrationBaseURL,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(rewriteIntegrationUsername, rewriteIntegrationPassword),
		adguard.WithUserAgent(rewriteIntegrationUserAgent),
	)
	require.NoError(t, err)

	return client
}
