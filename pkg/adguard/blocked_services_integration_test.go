// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// blockedServicesIntegrationCall invokes one blocked-services operation.
type blockedServicesIntegrationCall func(context.Context, *adguard.Client) error

// blockedServicesIntegrationRequestCapture contains one captured HTTP request.
type blockedServicesIntegrationRequestCapture struct {
	method        string
	path          string
	rawQuery      string
	accept        string
	contentType   string
	contentLength int64
	username      string
	password      string
	userAgent     string
	body          []byte
	readErr       error
	closeErr      error
	hasAuth       bool
}

// blockedServicesIntegrationSuccessCase describes one successful HTTP exchange.
type blockedServicesIntegrationSuccessCase struct {
	name                string
	method              string
	path                string
	requestBody         string
	responseBody        string
	responseContentType string
	responseStatus      int
	call                func(context.Context, *adguard.Client) (any, error)
	verify              func(*testing.T, any)
}

// blockedServicesIntegrationSchedulePresenceCase describes one schedule presence response.
type blockedServicesIntegrationSchedulePresenceCase struct {
	name   string
	body   string
	verify func(*testing.T, *adguard.BlockedServicesSchedule)
}

// blockedServicesIntegrationOperationCase describes one blocked-services operation.
type blockedServicesIntegrationOperationCase struct {
	name      string
	operation string
	method    string
	call      blockedServicesIntegrationCall
}

// blockedServicesIntegrationLimitCase describes one response-limit contract.
type blockedServicesIntegrationLimitCase struct {
	name        string
	operation   string
	method      string
	contentType string
	body        string
	call        blockedServicesIntegrationCall
}

// blockedServicesIntegrationResponseErrorCase describes one response error.
type blockedServicesIntegrationResponseErrorCase struct {
	name            string
	operation       string
	method          string
	contentType     string
	body            string
	status          int
	wantKind        adguard.ErrorKind
	wantContentType string
	wantStatusCode  int
	wantStatus      string
	wantBody        string
	call            blockedServicesIntegrationCall
}

const (
	// The base URL is the API path used by the concrete client.
	blockedServicesIntegrationBaseURL = "http://127.0.0.1/api/"
	// The username is the expected Basic authentication username.
	blockedServicesIntegrationUsername = "blocked-services-integration-user"
	// The password is the expected Basic authentication password.
	blockedServicesIntegrationPassword = "blocked-services-integration-password"
	// The User-Agent is the expected client User-Agent.
	blockedServicesIntegrationUserAgent = "blocked-services-integration-client/1.0"
	// The JSON content type is the successful JSON media type.
	blockedServicesIntegrationJSONContentType = "application/json"
	// The response limit is the default response body limit.
	blockedServicesIntegrationResponseLimit int64 = 4096
	// The cancellation timeout bounds cancellation coordination.
	blockedServicesIntegrationCancellationTimeout = time.Second
	// The redirect location is the rejected redirect target.
	blockedServicesIntegrationRedirectLocation = "http://127.0.0.1/api/blocked-services-redirect"
	// The status body is a bounded structured status response.
	blockedServicesIntegrationStatusBody = `{"message":"blocked services unavailable"}`
	// The catalog is a complete catalog response.
	blockedServicesIntegrationCatalog = `{
		"blocked_services": [
			{"icon_svg":"<svg/>","id":"youtube","name":"YouTube","rules":["||youtube^"],"group_id":"media"},
			{"icon_svg":"","id":"empty","name":"Empty","rules":[]}
		],
		"groups": [{"id":"media"}],
		"future_field": true
	}`
	// The schedule is a complete schedule response.
	blockedServicesIntegrationSchedule = `{
		"schedule": {
			"time_zone":"UTC",
			"sun":{"start":0,"end":0},
			"mon":null
		},
		"ids":["youtube","reddit"]
	}`
	// The catalog test name identifies the catalog operation.
	blockedServicesIntegrationCatalogName = "catalog"
	// The schedule test name identifies the schedule operation.
	blockedServicesIntegrationScheduleName = "schedule"
	// The update test name identifies the update operation.
	blockedServicesIntegrationUpdateName = "update"
	// The catalog operation identifies catalog errors.
	blockedServicesIntegrationCatalogOperation = "blocked_services_all"
	// The schedule operation identifies schedule errors.
	blockedServicesIntegrationScheduleOperation = "blocked_services_schedule"
	// The update operation identifies update errors.
	blockedServicesIntegrationUpdateOperation = "blocked_services_schedule_update"
	// The problem media type is used for structured status responses.
	blockedServicesIntegrationProblemContentType = "application/problem+json"
	// The Reddit identifier appears in the schedule identifier list.
	blockedServicesIntegrationRedditKey = "reddit"
)

// TestBlockedServicesIntegrationRequestContracts verifies every blocked-services HTTP request contract.
func TestBlockedServicesIntegrationRequestContracts(t *testing.T) {
	t.Parallel()

	for _, test := range blockedServicesIntegrationSuccessCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan blockedServicesIntegrationRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured <- captureBlockedServicesIntegrationRequest(r)

				writeBlockedServicesIntegrationResponse(
					w,
					test.responseContentType,
					test.responseStatus,
					test.responseBody,
				)
			}))
			client := newBlockedServicesIntegrationClient(t, server)

			result, err := test.call(t.Context(), client)

			require.NoError(t, err)

			request := <-captured
			assertBlockedServicesIntegrationRequest(t, test, request)

			if test.verify != nil {
				test.verify(t, result)
			}
		})
	}
}

// TestBlockedServicesIntegrationSchedulePresence verifies absent, null, empty, and explicit schedule values.
func TestBlockedServicesIntegrationSchedulePresence(t *testing.T) {
	t.Parallel()

	tests := blockedServicesIntegrationSchedulePresenceCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newBlockedServicesIntegrationResponseServer(
				t,
				blockedServicesIntegrationJSONContentType,
				http.StatusOK,
				test.body,
			)
			client := newBlockedServicesIntegrationClient(t, server)

			schedule, err := client.BlockedServicesSchedule(t.Context())

			require.NoError(t, err)
			require.NotNil(t, schedule)
			test.verify(t, schedule)
		})
	}
}

// blockedServicesIntegrationSchedulePresenceCases returns schedule presence cases.
//
// Returns:
//   - cases: Schedule response fixtures and their field-presence assertions.
func blockedServicesIntegrationSchedulePresenceCases() []blockedServicesIntegrationSchedulePresenceCase {
	return []blockedServicesIntegrationSchedulePresenceCase{
		{
			name: safetyIntegrationAbsentName,
			body: `{}`,
			verify: func(t *testing.T, schedule *adguard.BlockedServicesSchedule) {
				t.Helper()

				assert.Nil(t, schedule.Schedule)
				assert.Nil(t, schedule.IDs)
			},
		},
		{
			name: safetyIntegrationNullName,
			body: `{"schedule":null,"ids":null}`,
			verify: func(t *testing.T, schedule *adguard.BlockedServicesSchedule) {
				t.Helper()

				assert.Nil(t, schedule.Schedule)
				assert.Nil(t, schedule.IDs)
			},
		},
		{
			name: "empty",
			body: `{"schedule":{},"ids":[]}`,
			verify: func(t *testing.T, schedule *adguard.BlockedServicesSchedule) {
				t.Helper()

				require.NotNil(t, schedule.Schedule)
				assert.Nil(t, schedule.Schedule.TimeZone)
				assert.Nil(t, schedule.Schedule.Sun)
				require.NotNil(t, schedule.IDs)
				assert.Empty(t, *schedule.IDs)
			},
		},
		{
			name: "explicit zero and empty string",
			body: `{"schedule":{"time_zone":"","sun":{"start":0,"end":0}},"ids":[""]}`,
			verify: func(t *testing.T, schedule *adguard.BlockedServicesSchedule) {
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
				assert.Equal(t, []string{""}, *schedule.IDs)
			},
		},
	}
}

// TestBlockedServicesIntegrationUpdatePresence verifies omitted, empty, and explicit update properties.
func TestBlockedServicesIntegrationUpdatePresence(t *testing.T) {
	t.Parallel()

	emptyIDs := []string{}
	emptyTimeZone := ""
	zero := 0.0
	emptySchedule := adguard.Schedule{}
	explicitSchedule := adguard.Schedule{
		TimeZone: &emptyTimeZone,
		Sun: &adguard.DayRange{
			Start: &zero,
			End:   &zero,
		},
	}
	tests := []struct {
		name        string
		schedule    adguard.BlockedServicesSchedule
		requestBody string
	}{
		{
			name:        "all properties omitted",
			schedule:    adguard.BlockedServicesSchedule{},
			requestBody: `{}`,
		},
		{
			name:        "empty schedule object",
			schedule:    adguard.BlockedServicesSchedule{Schedule: &emptySchedule},
			requestBody: `{"schedule":{}}`,
		},
		{
			name:        "empty identifier list",
			schedule:    adguard.BlockedServicesSchedule{IDs: &emptyIDs},
			requestBody: `{"ids":[]}`,
		},
		{
			name: "explicit empty and zero values",
			schedule: adguard.BlockedServicesSchedule{
				Schedule: &explicitSchedule,
				IDs:      &emptyIDs,
			},
			requestBody: `{"schedule":{"time_zone":"","sun":{"start":0,"end":0}},"ids":[]}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			captured := make(chan blockedServicesIntegrationRequestCapture, 1)
			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				captured <- captureBlockedServicesIntegrationRequest(r)

				w.WriteHeader(http.StatusNoContent)
			}))
			client := newBlockedServicesIntegrationClient(t, server)

			err := client.BlockedServicesScheduleUpdate(t.Context(), test.schedule)

			require.NoError(t, err)

			request := <-captured
			assert.Equal(t, http.MethodPut, request.method)
			assert.Equal(t, "/api/control/blocked_services/update", request.path)
			//nolint:testifylint // encoded-compare: Content-Type is a media type, not encoded JSON.
			assert.Equal(t, blockedServicesIntegrationJSONContentType, request.contentType)
			assert.Equal(t, int64(len(test.requestBody)), request.contentLength)
			assert.JSONEq(t, test.requestBody, string(request.body))
			assert.True(t, request.hasAuth)
		})
	}
}

// TestBlockedServicesIntegrationResponseModes verifies reads require JSON and updates accept empty success bodies.
func TestBlockedServicesIntegrationResponseModes(t *testing.T) {
	t.Parallel()

	t.Run("read accepts JSON parameters", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesIntegrationResponseServer(
			t,
			blockedServicesIntegrationJSONContentType+"; charset=utf-8",
			http.StatusOK,
			blockedServicesIntegrationSchedule,
		)
		client := newBlockedServicesIntegrationClient(t, server)

		schedule, err := client.BlockedServicesSchedule(t.Context())

		require.NoError(t, err)
		require.NotNil(t, schedule)
	})

	t.Run("read rejects empty response", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesIntegrationResponseServer(
			t,
			blockedServicesIntegrationJSONContentType,
			http.StatusOK,
			"",
		)
		client := newBlockedServicesIntegrationClient(t, server)

		_, err := client.BlockedServicesSchedule(t.Context())

		clientErr := requireBlockedServicesIntegrationError(t, err, adguard.ErrorKindJSON)
		assert.Equal(t, blockedServicesIntegrationScheduleOperation, clientErr.Operation)
		assert.Equal(t, http.MethodGet, clientErr.Method)
	})

	t.Run("update accepts JSON response", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesIntegrationResponseServer(
			t,
			blockedServicesIntegrationJSONContentType,
			http.StatusOK,
			`{"status":"updated"}`,
		)
		client := newBlockedServicesIntegrationClient(t, server)

		err := client.BlockedServicesScheduleUpdate(
			t.Context(),
			adguard.BlockedServicesSchedule{},
		)

		require.NoError(t, err)
	})

	t.Run("update accepts empty response", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesIntegrationResponseServer(t, "", http.StatusNoContent, "")
		client := newBlockedServicesIntegrationClient(t, server)

		err := client.BlockedServicesScheduleUpdate(
			t.Context(),
			adguard.BlockedServicesSchedule{},
		)

		require.NoError(t, err)
	})

	t.Run("update accepts non-JSON response", func(t *testing.T) {
		t.Parallel()

		server := newBlockedServicesIntegrationResponseServer(
			t,
			"text/plain; charset=utf-8",
			http.StatusOK,
			"update accepted",
		)
		client := newBlockedServicesIntegrationClient(t, server)

		err := client.BlockedServicesScheduleUpdate(
			t.Context(),
			adguard.BlockedServicesSchedule{},
		)

		require.NoError(t, err)
	})
}

// TestBlockedServicesIntegrationStructuredErrors verifies response, status, and JSON error metadata.
func TestBlockedServicesIntegrationStructuredErrors(t *testing.T) {
	t.Parallel()

	cases := blockedServicesIntegrationResponseErrorCases()
	for index := range cases {
		test := &cases[index]
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newBlockedServicesIntegrationResponseServer(
				t,
				test.contentType,
				test.status,
				test.body,
			)
			client := newBlockedServicesIntegrationClient(t, server)

			err := test.call(t.Context(), client)

			clientErr := requireBlockedServicesIntegrationError(t, err, test.wantKind)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, test.wantStatusCode, clientErr.StatusCode)
			assert.Equal(t, test.wantStatus, clientErr.Status)
			assert.Equal(t, test.wantContentType, clientErr.ContentType)
			assert.Equal(t, test.wantBody, string(clientErr.Body))
		})
	}
}

// TestBlockedServicesIntegrationMalformedInput verifies invalid update values fail before transport.
func TestBlockedServicesIntegrationMalformedInput(t *testing.T) {
	t.Parallel()

	invalidNumber := math.NaN()
	invalidUTF8 := string([]byte{0xff})
	ids := []string{invalidUTF8}
	tests := []struct {
		name     string
		schedule adguard.BlockedServicesSchedule
	}{
		{
			name: "non-finite number",
			schedule: adguard.BlockedServicesSchedule{
				Schedule: &adguard.Schedule{
					Sun: &adguard.DayRange{Start: &invalidNumber},
				},
			},
		},
		{
			name:     "invalid UTF-8 identifier",
			schedule: adguard.BlockedServicesSchedule{IDs: &ids},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var requests atomic.Int32

			server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			client := newBlockedServicesIntegrationClient(t, server)

			err := client.BlockedServicesScheduleUpdate(t.Context(), test.schedule)

			clientErr := requireBlockedServicesIntegrationError(t, err, adguard.ErrorKindJSON)
			assert.Equal(t, blockedServicesIntegrationUpdateOperation, clientErr.Operation)
			assert.Equal(t, http.MethodPut, clientErr.Method)
			assert.Zero(t, requests.Load())
		})
	}
}

// TestBlockedServicesIntegrationEnforcesResponseLimits verifies all operations enforce the configured bound.
func TestBlockedServicesIntegrationEnforcesResponseLimits(t *testing.T) {
	t.Parallel()

	tests := blockedServicesIntegrationLimitCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			server := newBlockedServicesIntegrationResponseServer(
				t,
				test.contentType,
				http.StatusOK,
				test.body,
			)
			limit := int64(1)
			client := newBlockedServicesIntegrationClient(
				t,
				server,
				adguard.WithMaxResponseBodySize(limit),
			)

			err := test.call(t.Context(), client)

			clientErr := requireBlockedServicesIntegrationError(t, err, adguard.ErrorKindResponseTooLarge)
			assert.Equal(t, test.operation, clientErr.Operation)
			assert.Equal(t, test.method, clientErr.Method)
			assert.Equal(t, http.StatusOK, clientErr.StatusCode)
			assert.Equal(t, limit, clientErr.Limit)
			assert.Equal(t, test.contentType, clientErr.ContentType)
			assert.Nil(t, clientErr.Body)
		})
	}
}

// TestBlockedServicesIntegrationPropagatesCancellation verifies every operation stops after cancellation.
func TestBlockedServicesIntegrationPropagatesCancellation(t *testing.T) {
	t.Parallel()

	for _, test := range blockedServicesIntegrationOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertBlockedServicesIntegrationCancellation(t, test)
		})
	}
}

// assertBlockedServicesIntegrationCancellation verifies one cancellation contract.
//
// Parameters:
//   - test: The operation contract to exercise.
func assertBlockedServicesIntegrationCancellation(
	t *testing.T,
	test blockedServicesIntegrationOperationCase,
) {
	t.Helper()

	requestStarted := make(chan struct{})
	server := httptest.NewTestServer(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, readErr := io.ReadAll(r.Body)
		closeErr := r.Body.Close()
		if readErr != nil || closeErr != nil {
			return
		}

		close(requestStarted)
		<-r.Context().Done()
	}))
	client := newBlockedServicesIntegrationClient(t, server)
	ctx, cancel := context.WithCancel(t.Context())

	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- test.call(ctx, client)
	}()

	select {
	case <-requestStarted:
	case <-time.After(blockedServicesIntegrationCancellationTimeout):
		cancel()
		t.Fatal("blocked-services request did not reach the test server")
	}

	cancel()

	var err error

	select {
	case err = <-result:
	case <-time.After(blockedServicesIntegrationCancellationTimeout):
		t.Fatal("blocked-services request did not return after cancellation")
	}

	clientErr := requireBlockedServicesIntegrationError(t, err, adguard.ErrorKindRequest)
	assert.Equal(t, test.operation, clientErr.Operation)
	assert.Equal(t, test.method, clientErr.Method)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestBlockedServicesIntegrationRejectsRedirects verifies redirects are blocked before forwarding credentials.
func TestBlockedServicesIntegrationRejectsRedirects(t *testing.T) {
	t.Parallel()

	for _, test := range blockedServicesIntegrationOperationCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assertBlockedServicesIntegrationRedirect(t, test)
		})
	}
}

// assertBlockedServicesIntegrationRedirect verifies one redirect contract.
//
// Parameters:
//   - test: The operation contract to exercise.
func assertBlockedServicesIntegrationRedirect(
	t *testing.T,
	test blockedServicesIntegrationOperationCase,
) {
	t.Helper()

	var redirectedRequests atomic.Int32

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/blocked-services-redirect" {
			redirectedRequests.Add(1)
			w.WriteHeader(http.StatusOK)

			return
		}

		http.Redirect(w, r, blockedServicesIntegrationRedirectLocation, http.StatusTemporaryRedirect)
	}))
	client := newBlockedServicesIntegrationClient(t, server)

	err := test.call(t.Context(), client)

	clientErr := requireBlockedServicesIntegrationError(t, err, adguard.ErrorKindRedirect)
	assert.Equal(t, test.operation, clientErr.Operation)
	assert.Equal(t, test.method, clientErr.Method)
	assert.Equal(t, blockedServicesIntegrationRedirectLocation, clientErr.Location)
	assert.Zero(t, redirectedRequests.Load())
}

// blockedServicesIntegrationOperationCases returns all blocked-services operation contracts.
//
// Returns:
//   - cases: Operation metadata and invokers for every blocked-services method.
func blockedServicesIntegrationOperationCases() []blockedServicesIntegrationOperationCase {
	return []blockedServicesIntegrationOperationCase{
		{
			name:      blockedServicesIntegrationCatalogName,
			operation: blockedServicesIntegrationCatalogOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.BlockedServicesAll(ctx)

				return err
			},
		},
		{
			name:      blockedServicesIntegrationScheduleName,
			operation: blockedServicesIntegrationScheduleOperation,
			method:    http.MethodGet,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.BlockedServicesSchedule(ctx)

				return err
			},
		},
		{
			name:      blockedServicesIntegrationUpdateName,
			operation: blockedServicesIntegrationUpdateOperation,
			method:    http.MethodPut,
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.BlockedServicesScheduleUpdate(
					ctx,
					adguard.BlockedServicesSchedule{},
				)
			},
		},
	}
}

// blockedServicesIntegrationLimitCases returns response-limit contracts.
//
// Returns:
//   - cases: Response-limit fixtures for every blocked-services operation.
func blockedServicesIntegrationLimitCases() []blockedServicesIntegrationLimitCase {
	return []blockedServicesIntegrationLimitCase{
		{
			name:        blockedServicesIntegrationCatalogName,
			operation:   blockedServicesIntegrationCatalogOperation,
			method:      http.MethodGet,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        blockedServicesIntegrationCatalog,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.BlockedServicesAll(ctx)

				return err
			},
		},
		{
			name:        blockedServicesIntegrationScheduleName,
			operation:   blockedServicesIntegrationScheduleOperation,
			method:      http.MethodGet,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        blockedServicesIntegrationSchedule,
			call: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.BlockedServicesSchedule(ctx)

				return err
			},
		},
		{
			name:        blockedServicesIntegrationUpdateName,
			operation:   blockedServicesIntegrationUpdateOperation,
			method:      http.MethodPut,
			contentType: installIntegrationTextMediaType,
			body:        "update response",
			call: func(ctx context.Context, client *adguard.Client) error {
				return client.BlockedServicesScheduleUpdate(
					ctx,
					adguard.BlockedServicesSchedule{},
				)
			},
		},
	}
}

// blockedServicesIntegrationSuccessCases returns every successful blocked-services contract.
//
// Returns:
//   - cases: Successful request and response contracts for every operation.
func blockedServicesIntegrationSuccessCases() []blockedServicesIntegrationSuccessCase {
	return []blockedServicesIntegrationSuccessCase{
		{
			name:                blockedServicesIntegrationCatalogName,
			method:              http.MethodGet,
			path:                "/api/control/blocked_services/all",
			responseBody:        blockedServicesIntegrationCatalog,
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseStatus:      http.StatusOK,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesAll(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				catalog, ok := result.(*adguard.BlockedServicesAll)
				require.True(t, ok)
				require.NotNil(t, catalog)
				require.Len(t, catalog.BlockedServices, 2)
				assert.Equal(t, "youtube", catalog.BlockedServices[0].ID)
				assert.Equal(t, []string{"||youtube^"}, catalog.BlockedServices[0].Rules)
				require.NotNil(t, catalog.BlockedServices[0].GroupID)
				assert.Equal(t, "media", *catalog.BlockedServices[0].GroupID)
				assert.Nil(t, catalog.BlockedServices[1].GroupID)
				require.Len(t, catalog.Groups, 1)
				assert.Equal(t, "media", catalog.Groups[0].ID)
			},
		},
		{
			name:                blockedServicesIntegrationScheduleName,
			method:              http.MethodGet,
			path:                "/api/control/blocked_services/get",
			responseBody:        blockedServicesIntegrationSchedule,
			responseContentType: blockedServicesIntegrationJSONContentType,
			responseStatus:      http.StatusOK,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.BlockedServicesSchedule(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				schedule, ok := result.(*adguard.BlockedServicesSchedule)
				require.True(t, ok)
				require.NotNil(t, schedule)
				require.NotNil(t, schedule.Schedule)
				require.NotNil(t, schedule.Schedule.TimeZone)
				assert.Equal(t, "UTC", *schedule.Schedule.TimeZone)
				require.NotNil(t, schedule.Schedule.Sun)
				require.NotNil(t, schedule.Schedule.Sun.Start)
				assert.Zero(t, *schedule.Schedule.Sun.Start)
				assert.Nil(t, schedule.Schedule.Mon)
				require.NotNil(t, schedule.IDs)
				assert.Equal(
					t,
					[]string{safetyIntegrationYouTubeKey, blockedServicesIntegrationRedditKey},
					*schedule.IDs,
				)
			},
		},
		{
			name:           "schedule update",
			method:         http.MethodPut,
			path:           "/api/control/blocked_services/update",
			requestBody:    `{}`,
			responseStatus: http.StatusNoContent,
			call: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.BlockedServicesScheduleUpdate(
					ctx,
					adguard.BlockedServicesSchedule{},
				)
			},
		},
	}
}

// blockedServicesIntegrationResponseErrorCases returns representative response failures.
//
// Returns:
//   - cases: JSON, media-type, and status error contracts.
func blockedServicesIntegrationResponseErrorCases() []blockedServicesIntegrationResponseErrorCase {
	cases := blockedServicesIntegrationJSONResponseErrorCases()

	return append(cases, blockedServicesIntegrationStatusResponseErrorCases()...)
}

// blockedServicesIntegrationJSONResponseErrorCases returns JSON and media-type failures.
//
// Returns:
//   - cases: Malformed JSON, null document, and media-type error contracts.
func blockedServicesIntegrationJSONResponseErrorCases() []blockedServicesIntegrationResponseErrorCase {
	return []blockedServicesIntegrationResponseErrorCase{
		{
			name:        "malformed catalog JSON",
			operation:   blockedServicesIntegrationCatalogOperation,
			method:      http.MethodGet,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        `{"blocked_services":`,
			status:      http.StatusOK,
			wantKind:    adguard.ErrorKindJSON,
			call:        blockedServicesIntegrationCatalogCall,
		},
		{
			name:        "null schedule",
			operation:   blockedServicesIntegrationScheduleOperation,
			method:      http.MethodGet,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        safetyIntegrationNullName,
			status:      http.StatusOK,
			wantKind:    adguard.ErrorKindJSON,
			call:        blockedServicesIntegrationScheduleCall,
		},
		{
			name:        "missing catalog group list",
			operation:   blockedServicesIntegrationCatalogOperation,
			method:      http.MethodGet,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        `{"blocked_services":[]}`,
			status:      http.StatusOK,
			wantKind:    adguard.ErrorKindJSON,
			call:        blockedServicesIntegrationCatalogCall,
		},
		{
			name:        "null schedule identifier",
			operation:   blockedServicesIntegrationScheduleOperation,
			method:      http.MethodGet,
			contentType: blockedServicesIntegrationJSONContentType,
			body:        `{"ids":[null]}`,
			status:      http.StatusOK,
			wantKind:    adguard.ErrorKindJSON,
			call:        blockedServicesIntegrationScheduleCall,
		},
		{
			name:            "wrong read media type",
			operation:       blockedServicesIntegrationScheduleOperation,
			method:          http.MethodGet,
			contentType:     installIntegrationTextMediaType,
			body:            blockedServicesIntegrationSchedule,
			status:          http.StatusOK,
			wantKind:        adguard.ErrorKindContentType,
			wantStatusCode:  http.StatusOK,
			wantStatus:      statusIntegrationOKStatus,
			wantContentType: installIntegrationTextMediaType,
			call:            blockedServicesIntegrationScheduleCall,
		},
	}
}

// blockedServicesIntegrationStatusResponseErrorCases returns structured status failures.
//
// Returns:
//   - cases: Non-success response contracts for every operation.
func blockedServicesIntegrationStatusResponseErrorCases() []blockedServicesIntegrationResponseErrorCase {
	return []blockedServicesIntegrationResponseErrorCase{
		{
			name:            "catalog status error",
			operation:       blockedServicesIntegrationCatalogOperation,
			method:          http.MethodGet,
			contentType:     blockedServicesIntegrationProblemContentType,
			body:            blockedServicesIntegrationStatusBody,
			status:          http.StatusServiceUnavailable,
			wantKind:        adguard.ErrorKindStatus,
			wantStatusCode:  http.StatusServiceUnavailable,
			wantStatus:      statusIntegrationUnavailableStatus,
			wantContentType: blockedServicesIntegrationProblemContentType,
			wantBody:        blockedServicesIntegrationStatusBody,
			call:            blockedServicesIntegrationCatalogCall,
		},
		{
			name:            "schedule status error",
			operation:       blockedServicesIntegrationScheduleOperation,
			method:          http.MethodGet,
			contentType:     blockedServicesIntegrationProblemContentType,
			body:            blockedServicesIntegrationStatusBody,
			status:          http.StatusUnprocessableEntity,
			wantKind:        adguard.ErrorKindStatus,
			wantStatusCode:  http.StatusUnprocessableEntity,
			wantStatus:      "422 Unprocessable Entity",
			wantContentType: blockedServicesIntegrationProblemContentType,
			wantBody:        blockedServicesIntegrationStatusBody,
			call:            blockedServicesIntegrationScheduleCall,
		},
		{
			name:            "update status error",
			operation:       blockedServicesIntegrationUpdateOperation,
			method:          http.MethodPut,
			contentType:     blockedServicesIntegrationProblemContentType,
			body:            blockedServicesIntegrationStatusBody,
			status:          http.StatusConflict,
			wantKind:        adguard.ErrorKindStatus,
			wantStatusCode:  http.StatusConflict,
			wantStatus:      "409 Conflict",
			wantContentType: blockedServicesIntegrationProblemContentType,
			wantBody:        blockedServicesIntegrationStatusBody,
			call:            blockedServicesIntegrationUpdateCall,
		},
	}
}

// blockedServicesIntegrationCatalogCall invokes the catalog operation.
//
// Parameters:
//   - ctx: The request context.
//   - client: The concrete AdGuard client.
//
// Returns:
//   - error: The operation error, if any.
func blockedServicesIntegrationCatalogCall(ctx context.Context, client *adguard.Client) error {
	_, err := client.BlockedServicesAll(ctx)

	return err
}

// blockedServicesIntegrationScheduleCall invokes the schedule operation.
//
// Parameters:
//   - ctx: The request context.
//   - client: The concrete AdGuard client.
//
// Returns:
//   - error: The operation error, if any.
func blockedServicesIntegrationScheduleCall(ctx context.Context, client *adguard.Client) error {
	_, err := client.BlockedServicesSchedule(ctx)

	return err
}

// blockedServicesIntegrationUpdateCall invokes the update operation.
//
// Parameters:
//   - ctx: The request context.
//   - client: The concrete AdGuard client.
//
// Returns:
//   - error: The operation error, if any.
func blockedServicesIntegrationUpdateCall(ctx context.Context, client *adguard.Client) error {
	return client.BlockedServicesScheduleUpdate(ctx, adguard.BlockedServicesSchedule{})
}

// newBlockedServicesIntegrationResponseServer creates a server returning one fixed response.
//
// Parameters:
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP response status.
//   - body: The response body.
//
// Returns:
//   - server: The running test server.
func newBlockedServicesIntegrationResponseServer(
	t *testing.T,
	contentType string,
	status int,
	body string,
) *httptest.Server {
	t.Helper()

	return httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}

		w.WriteHeader(status)
		writeBlockedServicesIntegrationBody(w, body)
	}))
}

// newBlockedServicesIntegrationClient creates a concrete client for a blocked-services server.
//
// Parameters:
//   - server: The in-memory HTTP test server.
//   - options: Additional client options appended after the test defaults.
//
// Returns:
//   - client: The configured concrete client.
func newBlockedServicesIntegrationClient(
	t *testing.T,
	server *httptest.Server,
	options ...adguard.Option,
) *adguard.Client {
	t.Helper()

	allOptions := make([]adguard.Option, 0, len(options)+4)

	allOptions = append(
		allOptions,
		adguard.WithHTTPClient(server.Client()),
		adguard.WithBasicAuth(blockedServicesIntegrationUsername, blockedServicesIntegrationPassword),
		adguard.WithUserAgent(blockedServicesIntegrationUserAgent),
		adguard.WithMaxResponseBodySize(blockedServicesIntegrationResponseLimit),
	)
	allOptions = append(allOptions, options...)

	client, err := adguard.NewClient(blockedServicesIntegrationBaseURL, allOptions...)
	require.NoError(t, err)

	return client
}

// captureBlockedServicesIntegrationRequest reads and records one HTTP request.
//
// Parameters:
//   - request: The request received by the test server.
//
// Returns:
//   - capture: The request metadata and body.
func captureBlockedServicesIntegrationRequest(request *http.Request) blockedServicesIntegrationRequestCapture {
	body, readErr := io.ReadAll(request.Body)
	closeErr := request.Body.Close()
	username, password, hasAuth := request.BasicAuth()

	return blockedServicesIntegrationRequestCapture{
		method:        request.Method,
		path:          request.URL.Path,
		rawQuery:      request.URL.RawQuery,
		accept:        request.Header.Get("Accept"),
		contentType:   request.Header.Get("Content-Type"),
		contentLength: request.ContentLength,
		username:      username,
		password:      password,
		userAgent:     request.Header.Get("User-Agent"),
		body:          body,
		readErr:       readErr,
		closeErr:      closeErr,
		hasAuth:       hasAuth,
	}
}

// assertBlockedServicesIntegrationRequest verifies the common request contract.
//
// Parameters:
//   - test: The expected request and response contract.
//   - request: The captured HTTP request.
func assertBlockedServicesIntegrationRequest(
	t *testing.T,
	test blockedServicesIntegrationSuccessCase,
	request blockedServicesIntegrationRequestCapture,
) {
	t.Helper()

	require.NoError(t, request.readErr)
	require.NoError(t, request.closeErr)
	assert.Equal(t, test.method, request.method)
	assert.Equal(t, test.path, request.path)
	assert.Empty(t, request.rawQuery)
	//nolint:testifylint // encoded-compare: Accept is a media type, not encoded JSON.
	assert.Equal(t, blockedServicesIntegrationJSONContentType, request.accept)
	assert.Equal(t, blockedServicesIntegrationUserAgent, request.userAgent)
	assert.True(t, request.hasAuth)
	assert.Equal(t, blockedServicesIntegrationUsername, request.username)
	assert.Equal(t, blockedServicesIntegrationPassword, request.password)

	if test.method == http.MethodGet {
		assert.Zero(t, request.contentLength)
		assert.Empty(t, request.contentType)
		assert.Empty(t, request.body)

		return
	}

	assert.Equal(t, int64(len(test.requestBody)), request.contentLength)
	//nolint:testifylint // encoded-compare: Content-Type is a media type, not encoded JSON.
	assert.Equal(t, blockedServicesIntegrationJSONContentType, request.contentType)
	assert.JSONEq(t, test.requestBody, string(request.body))
}

// requireBlockedServicesIntegrationError extracts a structured client error.
//
// Parameters:
//   - err: The error returned by the client.
//   - kind: The expected structured error kind.
//
// Returns:
//   - clientErr: The extracted client error.
func requireBlockedServicesIntegrationError(
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

// writeBlockedServicesIntegrationResponse writes a response while tolerating disconnects.
//
// Parameters:
//   - w: The response writer.
//   - contentType: The response media type, or an empty string to omit it.
//   - status: The HTTP response status.
//   - body: The response body.
func writeBlockedServicesIntegrationResponse(w http.ResponseWriter, contentType string, status int, body string) {
	if contentType != "" {
		w.Header().Set("Content-Type", contentType)
	}

	w.WriteHeader(status)
	writeBlockedServicesIntegrationBody(w, body)
}

// writeBlockedServicesIntegrationBody writes a response body while tolerating disconnects.
//
// Parameters:
//   - w: The response writer.
//   - body: The response body.
func writeBlockedServicesIntegrationBody(w http.ResponseWriter, body string) {
	if body == "" {
		return
	}

	_, err := w.Write([]byte(body))
	if err != nil {
		return
	}
}
