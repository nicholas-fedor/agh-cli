// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockedServicesRequestCapture records one observed blocked-services request.
type blockedServicesRequestCapture struct {
	accept      string
	body        []byte
	contentType string
	hasAuth     bool
	method      string
	password    string
	path        string
	query       string
	readErr     error
	userAgent   string
	username    string
}

// blockedServicesCall invokes one blocked-services operation under test.
type blockedServicesCall func(context.Context, *Client) error

// blockedServicesContract pins one blocked-services request or response contract.
type blockedServicesContract struct {
	call           blockedServicesCall
	contentType    string
	method         string
	name           string
	path           string
	requestBody    string
	responseBody   string
	responseStatus int
}

const (
	// BlockedServicesTestBasePath is the common prefix for blocked-services endpoints.
	blockedServicesTestBasePath = "/api/control/blocked_services/"
	// BlockedServicesTestUser is the Basic authentication username for blocked-services fixtures.
	blockedServicesTestUser = "blocked-services-user"
	// BlockedServicesTestPassword is the Basic authentication password for blocked-services fixtures.
	blockedServicesTestPassword = "blocked-services-password"
	// BlockedServicesTestAgent is the expected client User-Agent for blocked-services fixtures.
	blockedServicesTestAgent = "agh-cli-blocked-services-test/1.0"
	// BlockedServicesTestLimit is the normal blocked-services response-body limit.
	blockedServicesTestLimit = int64(4096)
	// AdguardTestScheduleField is the schedule field name in decoded response objects.
	adguardTestScheduleField = "schedule"
	// AdguardTestIDsField is the identifier-list field name in decoded response objects.
	adguardTestIDsField = "ids"
	// TestResponseMediaType is the successful JSON response media type.
	testResponseMediaType = "application/json"
	// BlockedServicesTestCatalog is a minimal blocked-services catalog response.
	blockedServicesTestCatalog = `{
		"blocked_services":[
			{"icon_svg":"abc","id":"youtube","name":"YouTube","rules":["||youtube^"],"group_id":"media"},
			{"icon_svg":"","id":"empty","name":"Empty","rules":[]}
		],
		"groups":[{"id":"media"}],
		"future_field":true
	}`
	// BlockedServicesTestSchedule is a minimal blocked-services schedule response.
	blockedServicesTestSchedule = `{
		"schedule":{
			"time_zone":"Europe/Brussels",
			"sun":{"start":0,"end":0},
			"mon":null
		},
		"ids":["youtube"]
	}`
)

// TestClientBlockedServicesRequestContracts verifies the exact paths, methods,
// authentication headers, and request bodies for all supported operations.
func TestClientBlockedServicesRequestContracts(t *testing.T) {
	t.Parallel()

	for _, contract := range blockedServicesContracts() {
		t.Run(contract.name, func(t *testing.T) {
			t.Parallel()

			server, captured := newBlockedServicesRequestServer(t, contract)
			client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

			err := contract.call(t.Context(), client)
			require.NoError(t, err)

			request := <-captured
			assertBlockedServicesRequest(t, contract, request)
		})
	}
}

// TestClientBlockedServicesCatalogDecoding verifies required catalog fields and
// optional group identifiers.
func TestClientBlockedServicesCatalogDecoding(t *testing.T) {
	t.Parallel()

	server := newBlockedServicesResponseServer(
		t,
		testResponseMediaType,
		blockedServicesTestCatalog,
		http.StatusOK,
	)
	client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

	catalog, err := client.BlockedServicesAll(t.Context())

	require.NoError(t, err)
	require.NotNil(t, catalog)
	require.Len(t, catalog.BlockedServices, 2)
	assert.Equal(t, "abc", catalog.BlockedServices[0].IconSVG)
	assert.Equal(t, "youtube", catalog.BlockedServices[0].ID)
	assert.Equal(t, "YouTube", catalog.BlockedServices[0].Name)
	assert.Equal(t, []string{"||youtube^"}, catalog.BlockedServices[0].Rules)
	require.NotNil(t, catalog.BlockedServices[0].GroupID)
	assert.Equal(t, "media", *catalog.BlockedServices[0].GroupID)
	assert.Empty(t, catalog.BlockedServices[1].Rules)
	assert.Nil(t, catalog.BlockedServices[1].GroupID)
	require.Len(t, catalog.Groups, 1)
	assert.Equal(t, "media", catalog.Groups[0].ID)
}

// TestClientBlockedServicesCatalogRequiredFields verifies missing and null
// required catalog values produce structured JSON errors.
func TestClientBlockedServicesCatalogRequiredFields(t *testing.T) {
	t.Parallel()

	tests := []struct {
		body string
		name string
	}{
		{name: "top-level null", body: `null`},
		{name: "missing services", body: `{"groups":[]}`},
		{name: "null services", body: `{"blocked_services":null,"groups":[]}`},
		{name: "missing groups", body: `{"blocked_services":[]}`},
		{name: "null service", body: `{"blocked_services":[null],"groups":[]}`},
		{
			name: "missing service rules",
			body: `{"blocked_services":[{"icon_svg":"","id":"id","name":"name"}],"groups":[]}`,
		},
		{name: "null group", body: `{"blocked_services":[],"groups":[null]}`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newBlockedServicesResponseServer(
				t,
				testResponseMediaType,
				test.body,
				http.StatusOK,
			)
			client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

			catalog, err := client.BlockedServicesAll(t.Context())

			assert.Nil(t, catalog)

			clientErr := requireBlockedServicesError(t, err, ErrorKindJSON)
			assert.Equal(t, "blocked_services_all", clientErr.Operation)
			assert.Equal(t, http.MethodGet, clientErr.Method)
		})
	}
}

// TestClientBlockedServicesSchedulePresence verifies absent, null, empty, and
// explicit-zero schedule values.
func TestClientBlockedServicesSchedulePresence(t *testing.T) {
	t.Parallel()

	tests := []struct {
		assert func(*testing.T, *BlockedServicesSchedule)
		body   string
		name   string
	}{
		{
			name: "absent",
			body: `{}`,
			assert: func(t *testing.T, schedule *BlockedServicesSchedule) {
				t.Helper()
				assert.Nil(t, schedule.Schedule)
				assert.Nil(t, schedule.IDs)
			},
		},
		{
			name: "null",
			body: `{"schedule":null,"ids":null}`,
			assert: func(t *testing.T, schedule *BlockedServicesSchedule) {
				t.Helper()
				assert.Nil(t, schedule.Schedule)
				assert.Nil(t, schedule.IDs)
			},
		},
		{
			name: "empty",
			body: `{"schedule":{},"ids":[]}`,
			assert: func(t *testing.T, schedule *BlockedServicesSchedule) {
				t.Helper()
				require.NotNil(t, schedule.Schedule)
				assert.Nil(t, schedule.Schedule.TimeZone)
				assert.Nil(t, schedule.Schedule.Sun)
				require.NotNil(t, schedule.IDs)
				assert.Empty(t, *schedule.IDs)
			},
		},
		{
			name: "explicit zero",
			body: `{"schedule":{"time_zone":"","sun":{"start":0,"end":0}},"ids":[]}`,
			assert: func(t *testing.T, schedule *BlockedServicesSchedule) {
				t.Helper()
				require.NotNil(t, schedule.Schedule)
				require.NotNil(t, schedule.Schedule.TimeZone)
				assert.Empty(t, *schedule.Schedule.TimeZone)
				require.NotNil(t, schedule.Schedule.Sun)
				require.NotNil(t, schedule.Schedule.Sun.Start)
				assert.Zero(t, *schedule.Schedule.Sun.Start)
				require.NotNil(t, schedule.Schedule.Sun.End)
				assert.Zero(t, *schedule.Schedule.Sun.End)
				require.NotNil(t, schedule.IDs)
				assert.Empty(t, *schedule.IDs)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newBlockedServicesResponseServer(
				t,
				testResponseMediaType,
				test.body,
				http.StatusOK,
			)
			client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

			schedule, err := client.BlockedServicesSchedule(t.Context())

			require.NoError(t, err)
			require.NotNil(t, schedule)
			test.assert(t, schedule)
		})
	}
}

// TestClientBlockedServicesScheduleUpdateBody verifies that update always sends
// a JSON object and preserves explicit empty and zero properties.
func TestClientBlockedServicesScheduleUpdateBody(t *testing.T) {
	t.Parallel()

	emptyIDs := []string{}
	emptyTimeZone := ""
	zero := 0.0
	schedule := BlockedServicesSchedule{
		Schedule: &Schedule{
			TimeZone: &emptyTimeZone,
			Sun:      &DayRange{Start: &zero, End: &zero},
		},
		IDs: &emptyIDs,
	}

	tests := []struct {
		body     string
		name     string
		schedule BlockedServicesSchedule
	}{
		{name: "all properties omitted", schedule: BlockedServicesSchedule{}, body: `{}`},
		{
			name:     "explicit empty and zero values",
			schedule: schedule,
			body:     `{"schedule":{"time_zone":"","sun":{"start":0,"end":0}},"ids":[]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server, captured := newBlockedServicesRequestServer(t, blockedServicesContract{
				contentType:    "",
				method:         http.MethodPut,
				path:           "/api/control/blocked_services/update",
				responseBody:   "",
				responseStatus: http.StatusOK,
			})
			client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

			err := client.BlockedServicesScheduleUpdate(t.Context(), test.schedule)

			require.NoError(t, err)

			request := <-captured
			require.NoError(t, request.readErr)
			assert.JSONEq(t, test.body, string(request.body))
		})
	}
}

// TestClientBlockedServicesResponseModes verifies JSON responses for reads and
// body-agnostic successful responses for updates.
func TestClientBlockedServicesResponseModes(t *testing.T) {
	t.Parallel()

	t.Run("update accepts empty response", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesResponseServer(t, "", "", http.StatusOK)
		client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

		err := client.BlockedServicesScheduleUpdate(
			t.Context(),
			BlockedServicesSchedule{},
		)

		require.NoError(t, err)
	})

	t.Run("update accepts non-JSON success", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesResponseServer(t, "text/plain", "accepted", http.StatusOK)
		client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

		err := client.BlockedServicesScheduleUpdate(
			t.Context(),
			BlockedServicesSchedule{},
		)

		require.NoError(t, err)
	})
}

// TestClientBlockedServicesResponseErrors verifies content-type, JSON, status,
// response-limit, and cancellation errors retain structured metadata.
//
//nolint:revive // The explicit blocked-services error matrix intentionally stays in one test.
func TestClientBlockedServicesResponseErrors(t *testing.T) {
	t.Parallel()

	t.Run("read content type", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesResponseServer(t, "text/plain", `{}`, http.StatusOK)
		client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

		catalog, err := client.BlockedServicesAll(t.Context())

		assert.Nil(t, catalog)

		clientErr := requireBlockedServicesError(t, err, ErrorKindContentType)
		assert.Equal(t, "blocked_services_all", clientErr.Operation)
		assert.Equal(t, http.MethodGet, clientErr.Method)
		assert.Equal(t, "text/plain", clientErr.ContentType)
	})

	t.Run("read malformed JSON", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesResponseServer(
			t,
			testResponseMediaType,
			`{"blocked_services":`,
			http.StatusOK,
		)
		client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

		schedule, err := client.BlockedServicesSchedule(t.Context())

		assert.Nil(t, schedule)

		clientErr := requireBlockedServicesError(t, err, ErrorKindJSON)
		assert.Equal(t, "blocked_services_schedule", clientErr.Operation)
		assert.Equal(t, http.MethodGet, clientErr.Method)
	})

	t.Run("status errors", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			call      blockedServicesCall
			method    string
			name      string
			operation string
		}{
			{
				name:      "catalog",
				operation: "blocked_services_all",
				method:    http.MethodGet,
				call: func(ctx context.Context, client *Client) error {
					_, err := client.BlockedServicesAll(ctx)

					return err
				},
			},
			{
				name:      "schedule",
				operation: "blocked_services_schedule",
				method:    http.MethodGet,
				call: func(ctx context.Context, client *Client) error {
					_, err := client.BlockedServicesSchedule(ctx)

					return err
				},
			},
			{
				name:      "update",
				operation: "blocked_services_schedule_update",
				method:    http.MethodPut,
				call: func(ctx context.Context, client *Client) error {
					return client.BlockedServicesScheduleUpdate(
						ctx,
						BlockedServicesSchedule{},
					)
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				server := newBlockedServicesResponseServer(
					t,
					"text/plain",
					"blocked services failure",
					http.StatusUnprocessableEntity,
				)
				client := newBlockedServicesClient(t, server, blockedServicesTestLimit)

				err := test.call(t.Context(), client)

				clientErr := requireBlockedServicesError(t, err, ErrorKindStatus)
				assert.Equal(t, test.operation, clientErr.Operation)
				assert.Equal(t, test.method, clientErr.Method)
				assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
				assert.Equal(t, "blocked services failure", string(clientErr.Body))
			})
		}
	})

	t.Run("response limits", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			call      blockedServicesCall
			method    string
			name      string
			operation string
		}{
			{
				name:      "catalog",
				operation: "blocked_services_all",
				method:    http.MethodGet,
				call: func(ctx context.Context, client *Client) error {
					_, err := client.BlockedServicesAll(ctx)

					return err
				},
			},
			{
				name:      "schedule",
				operation: "blocked_services_schedule",
				method:    http.MethodGet,
				call: func(ctx context.Context, client *Client) error {
					_, err := client.BlockedServicesSchedule(ctx)

					return err
				},
			},
			{
				name:      "update",
				operation: "blocked_services_schedule_update",
				method:    http.MethodPut,
				call: func(ctx context.Context, client *Client) error {
					return client.BlockedServicesScheduleUpdate(
						ctx,
						BlockedServicesSchedule{},
					)
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				server := newBlockedServicesResponseServer(
					t,
					testResponseMediaType,
					`{"blocked_services":[],"groups":[]}`,
					http.StatusOK,
				)
				client := newBlockedServicesClient(t, server, 1)

				err := test.call(t.Context(), client)

				clientErr := requireBlockedServicesError(t, err, ErrorKindResponseTooLarge)
				assert.Equal(t, test.operation, clientErr.Operation)
				assert.Equal(t, test.method, clientErr.Method)
				assert.Equal(t, int64(1), clientErr.Limit)
			})
		}
	})

	t.Run("cancellation", func(t *testing.T) {
		t.Parallel()

		tests := []struct {
			call      blockedServicesCall
			method    string
			name      string
			operation string
		}{
			{
				name:      "catalog",
				operation: "blocked_services_all",
				method:    http.MethodGet,
				call: func(ctx context.Context, client *Client) error {
					_, err := client.BlockedServicesAll(ctx)

					return err
				},
			},
			{
				name:      "schedule",
				operation: "blocked_services_schedule",
				method:    http.MethodGet,
				call: func(ctx context.Context, client *Client) error {
					_, err := client.BlockedServicesSchedule(ctx)

					return err
				},
			},
			{
				name:      "update",
				operation: "blocked_services_schedule_update",
				method:    http.MethodPut,
				call: func(ctx context.Context, client *Client) error {
					return client.BlockedServicesScheduleUpdate(
						ctx,
						BlockedServicesSchedule{},
					)
				},
			},
		}

		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()

				server := newBlockedServicesResponseServer(t, "", "", http.StatusOK)
				client := newBlockedServicesClient(t, server, blockedServicesTestLimit)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				err := test.call(ctx, client)

				clientErr := requireBlockedServicesError(t, err, ErrorKindRequest)
				assert.Equal(t, test.operation, clientErr.Operation)
				assert.Equal(t, test.method, clientErr.Method)
				assert.ErrorIs(t, err, context.Canceled)
			})
		}
	})
}

// TestClientBlockedServicesUpdateEncodingError verifies invalid numeric values
// fail before transport with a structured JSON error.
func TestClientBlockedServicesUpdateEncodingError(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	client := newBlockedServicesClient(t, server, blockedServicesTestLimit)
	invalid := math.NaN()

	err := client.BlockedServicesScheduleUpdate(
		t.Context(),
		BlockedServicesSchedule{
			Schedule: &Schedule{Sun: &DayRange{Start: &invalid}},
		},
	)

	clientErr := requireBlockedServicesError(t, err, ErrorKindJSON)
	assert.Equal(t, "blocked_services_schedule_update", clientErr.Operation)
	assert.Equal(t, http.MethodPut, clientErr.Method)
	assert.Zero(t, requests.Load())
}

// blockedServicesContracts returns the successful HTTP contracts.
func blockedServicesContracts() []blockedServicesContract {
	return []blockedServicesContract{
		{
			name:           "all",
			method:         http.MethodGet,
			path:           blockedServicesTestBasePath + "all",
			contentType:    testResponseMediaType,
			responseBody:   blockedServicesTestCatalog,
			responseStatus: http.StatusOK,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.BlockedServicesAll(ctx)

				return err
			},
		},
		{
			name:           "schedule",
			method:         http.MethodGet,
			path:           blockedServicesTestBasePath + "get",
			contentType:    testResponseMediaType,
			responseBody:   blockedServicesTestSchedule,
			responseStatus: http.StatusOK,
			call: func(ctx context.Context, client *Client) error {
				_, err := client.BlockedServicesSchedule(ctx)

				return err
			},
		},
		{
			name:           "schedule update",
			method:         http.MethodPut,
			path:           blockedServicesTestBasePath + "update",
			requestBody:    `{}`,
			responseBody:   "",
			responseStatus: http.StatusOK,
			call: func(ctx context.Context, client *Client) error {
				return client.BlockedServicesScheduleUpdate(
					ctx,
					BlockedServicesSchedule{},
				)
			},
		},
	}
}

// assertBlockedServicesRequest verifies request metadata and body.
func assertBlockedServicesRequest(
	t *testing.T,
	contract blockedServicesContract,
	request blockedServicesRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	assert.Equal(t, contract.method, request.method)
	assert.Equal(t, contract.path, request.path)
	assert.Empty(t, request.query)
	assert.Equal(t, testResponseMediaType, request.accept)
	assert.Equal(t, blockedServicesTestAgent, request.userAgent)
	assert.True(t, request.hasAuth)
	assert.Equal(t, blockedServicesTestUser, request.username)
	assert.Equal(t, blockedServicesTestPassword, request.password)

	if contract.method == http.MethodPut {
		assert.Equal(t, testResponseMediaType, request.contentType)
		assert.JSONEq(t, contract.requestBody, string(request.body))
	} else {
		assert.Empty(t, request.contentType)
		assert.Empty(t, request.body)
	}
}

// newBlockedServicesRequestServer creates a server that captures one request.
func newBlockedServicesRequestServer(
	t *testing.T,
	contract blockedServicesContract,
) (*httptest.Server, <-chan blockedServicesRequestCapture) {
	t.Helper()

	captured := make(chan blockedServicesRequestCapture, 1)
	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if readErr == nil {
			readErr = closeErr
		}

		username, password, hasAuth := r.BasicAuth()
		captured <- blockedServicesRequestCapture{
			accept:      r.Header.Get("Accept"),
			body:        body,
			contentType: r.Header.Get("Content-Type"),
			hasAuth:     hasAuth,
			method:      r.Method,
			password:    password,
			path:        r.URL.Path,
			query:       r.URL.RawQuery,
			readErr:     readErr,
			userAgent:   r.Header.Get("User-Agent"),
			username:    username,
		}

		if contract.contentType != "" {
			w.Header().Set("Content-Type", contract.contentType)
		}

		w.WriteHeader(contract.responseStatus)

		if contract.responseBody != "" {
			_, _ = w.Write([]byte(contract.responseBody))
		}
	}))

	return server, captured
}

// newBlockedServicesResponseServer creates a server that returns a fixed response.
func newBlockedServicesResponseServer(
	t *testing.T,
	contentType string,
	body string,
	status int,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}

		w.WriteHeader(status)

		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
}

// newBlockedServicesClient creates a concrete client bound to a test server.
func newBlockedServicesClient(
	t *testing.T,
	server *httptest.Server,
	limit int64,
) *Client {
	t.Helper()

	client, err := NewClient(
		"http://127.0.0.1/api/",
		WithHTTPClient(server.Client()),
		WithBasicAuth(blockedServicesTestUser, blockedServicesTestPassword),
		WithUserAgent(blockedServicesTestAgent),
		WithMaxResponseBodySize(limit),
	)
	require.NoError(t, err)

	return client
}

// requireBlockedServicesError extracts and verifies a structured client error.
func requireBlockedServicesError(
	t *testing.T,
	err error,
	kind ErrorKind,
) *Error {
	t.Helper()

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, kind, clientErr.Kind)

	return clientErr
}
