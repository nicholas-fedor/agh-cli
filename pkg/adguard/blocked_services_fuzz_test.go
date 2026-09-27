// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"bytes"
	"encoding/json/v2"
	"math"
	"net/http"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// blockedServicesFuzzOperation describes one public blocked-services operation.
type blockedServicesFuzzOperation struct {
	// jsonResponse reports whether a successful response requires JSON.
	jsonResponse bool
	// method is the expected HTTP method.
	method string
	// name is the structured client operation name.
	name string
	// path is the expected endpoint path.
	path string
}

// blockedServicesFuzzState contains deterministic blocked-services fuzz state.
type blockedServicesFuzzState struct {
	// captures contains requests observed by the deterministic transport.
	captures []fuzzRequestCapture
	// client performs blocked-services operations without network access.
	client *Client
	// limit is the deterministic response body limit.
	limit int64
	// mode selects the deterministic response policy.
	mode byte
	// operation identifies the selected public operation.
	operation blockedServicesFuzzOperation
	// response contains the bounded response body.
	response []byte
}

const (
	// Blocked services request fuzzing bounds encoded model values.
	blockedServicesFuzzMaxRequestBytes = 128
	// Blocked services response fuzzing bounds JSON decoding and allocation.
	blockedServicesFuzzMaxResponseBytes = 8 << 10
	// Blocked services fuzz redirects remain inside the injected transport.
	blockedServicesFuzzRedirectLocation = "https://fuzz.invalid/blocked-services-redirect"
	// Blocked services opaque responses exercise the body-agnostic mode.
	blockedServicesFuzzTextMediaType = "text/plain; charset=utf-8"
)

const (
	// Response mode blockedServicesFuzzJSON returns a successful JSON response.
	blockedServicesFuzzJSON byte = iota
	// Response mode blockedServicesFuzzOpaque returns a successful non-JSON response.
	blockedServicesFuzzOpaque
	// Response mode blockedServicesFuzzStatus returns a non-success response.
	blockedServicesFuzzStatus
	// Response mode blockedServicesFuzzRedirect returns a client-rejected redirect.
	blockedServicesFuzzRedirect
	// Response mode blockedServicesFuzzTooLarge exceeds the configured limit.
	blockedServicesFuzzTooLarge
)

// FuzzBlockedServicesResponses exercises blocked-services response modes, redirects, and validation.
func FuzzBlockedServicesResponses(f *testing.F) {
	addBlockedServicesResponseFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, operation, mode byte, body []byte) {
		exerciseBlockedServicesResponseFuzz(t, operation, mode, body)
	})
}

// FuzzBlockedServicesRequestPresence exercises update encoding, validation, and optional-field presence.
func FuzzBlockedServicesRequestPresence(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x07})
	f.Add([]byte{0x0f, 0x7f, 0x03, 0x00, 'p', 'r', 'e', 's', 'e', 'n', 't'})
	f.Add([]byte{0x0f, 0x01, 0x01, 0xff, 'n', 'a', 'n'})
	f.Add([]byte("edge"))
	f.Add([]byte("9010"))

	f.Fuzz(func(t *testing.T, data []byte) {
		exerciseBlockedServicesRequestFuzz(t, data)
	})
}

// addBlockedServicesResponseFuzzSeeds registers deterministic bounded response fixtures.
func addBlockedServicesResponseFuzzSeeds(f *testing.F) {
	f.Helper()

	seeds := []struct {
		body      []byte
		mode      byte
		operation byte
	}{
		{
			operation: 0,
			mode:      blockedServicesFuzzJSON,
			body: []byte(`{
				"blocked_services":[
					{"icon_svg":"abc","id":"youtube","name":"YouTube","rules":["||youtube^"],"group_id":"media"},
					{"icon_svg":"","id":"empty","name":"Empty","rules":[]}
				],
				"groups":[{"id":"media"}]
			}`),
		},
		{
			operation: 0,
			mode:      blockedServicesFuzzJSON,
			body:      []byte(`{"blocked_services":[],"groups":[]}`),
		},
		{operation: 0, mode: blockedServicesFuzzJSON, body: []byte(`null`)},
		{operation: 0, mode: blockedServicesFuzzJSON, body: []byte(`{"groups":[]}`)},
		{
			operation: 0,
			mode:      blockedServicesFuzzJSON,
			body:      []byte(`{"blocked_services":[null],"groups":[{"id":null}]}`),
		},
		{operation: 0, mode: blockedServicesFuzzJSON, body: []byte(`{"blocked_services":`)},
		{operation: 0, mode: blockedServicesFuzzOpaque, body: []byte(`{"blocked_services":[],"groups":[]}`)},
		{operation: 0, mode: blockedServicesFuzzStatus, body: []byte(`rejected`)},
		{operation: 0, mode: blockedServicesFuzzRedirect, body: []byte(`redirect`)},
		{operation: 0, mode: blockedServicesFuzzTooLarge, body: []byte(`oversized catalog`)},
		{
			operation: 1,
			mode:      blockedServicesFuzzJSON,
			body: []byte(`{
				"schedule":{
					"time_zone":"Europe/Brussels",
					"sun":{"start":0,"end":0},
					"mon":null,
					"tue":{}
				},
				"ids":["youtube"]
			}`),
		},
		{operation: 1, mode: blockedServicesFuzzJSON, body: []byte(`{"schedule":{},"ids":[]}`)},
		{operation: 1, mode: blockedServicesFuzzJSON, body: []byte(`null`)},
		{operation: 1, mode: blockedServicesFuzzJSON, body: []byte(`{"ids":[null]}`)},
		{operation: 1, mode: blockedServicesFuzzJSON, body: []byte(`{"schedule":`)},
		{operation: 1, mode: blockedServicesFuzzOpaque, body: []byte(`{"schedule":{}}`)},
		{operation: 1, mode: blockedServicesFuzzStatus, body: []byte(`rejected`)},
		{operation: 1, mode: blockedServicesFuzzRedirect, body: []byte(`redirect`)},
		{operation: 1, mode: blockedServicesFuzzTooLarge, body: []byte(`oversized schedule`)},
		{operation: 2, mode: blockedServicesFuzzJSON, body: []byte(`{"blocked_services":[],"groups":[]}`)},
		{operation: 2, mode: blockedServicesFuzzOpaque, body: []byte(`accepted`)},
		{operation: 2, mode: blockedServicesFuzzStatus, body: []byte(`rejected`)},
		{operation: 2, mode: blockedServicesFuzzRedirect, body: []byte(`redirect`)},
		{operation: 2, mode: blockedServicesFuzzTooLarge, body: []byte(`oversized update response`)},
	}

	for _, seed := range seeds {
		f.Add(seed.operation, seed.mode, seed.body)
	}
}

// exerciseBlockedServicesResponseFuzz checks one bounded response operation.
func exerciseBlockedServicesResponseFuzz(t *testing.T, operation, mode byte, body []byte) {
	t.Helper()

	if len(body) > blockedServicesFuzzMaxResponseBytes {
		return
	}

	state := newBlockedServicesFuzzState(t, operation, mode, body)

	switch state.operation.name {
	case blockedServicesAllOperation:
		catalog, err := state.client.BlockedServicesAll(t.Context())
		requireBlockedServicesCatalogFuzzResult(t, state, catalog, err)
	case blockedServicesScheduleOperation:
		schedule, err := state.client.BlockedServicesSchedule(t.Context())
		requireBlockedServicesScheduleFuzzResult(t, state, schedule, err)
	case blockedServicesScheduleUpdateOperation:
		err := state.client.BlockedServicesScheduleUpdate(t.Context(), BlockedServicesSchedule{})
		requireBlockedServicesUpdateFuzzResult(t, state, err)
	default:
		require.Fail(t, "unreachable blocked-services operation", state.operation.name)
	}

	requireBlockedServicesFuzzRequest(t, state)
}

// newBlockedServicesFuzzState creates an offline client and deterministic response policy.
func newBlockedServicesFuzzState(
	t *testing.T,
	operationSelector byte,
	modeSelector byte,
	body []byte,
) *blockedServicesFuzzState {
	t.Helper()

	response := bytes.Clone(body)
	mode := modeSelector % (blockedServicesFuzzTooLarge + 1)
	if mode == blockedServicesFuzzTooLarge && len(response) < 2 {
		response = []byte("xx")
	}

	limit := max(int64(1), int64(len(response)))
	if mode == blockedServicesFuzzTooLarge {
		limit = max(int64(1), int64(len(response))/2)
	}

	state := &blockedServicesFuzzState{
		captures:  make([]fuzzRequestCapture, 0, 1),
		client:    nil,
		limit:     limit,
		mode:      mode,
		operation: selectBlockedServicesFuzzOperation(operationSelector),
		response:  response,
	}
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		state.captures = append(state.captures, capture)

		response := blockedServicesFuzzHTTPResponse(request, state)

		return response, nil
	})

	state.client = newFuzzClient(t, transport, state.limit)

	return state
}

// selectBlockedServicesFuzzOperation selects one public blocked-services operation.
func selectBlockedServicesFuzzOperation(selector byte) blockedServicesFuzzOperation {
	switch selector % 3 {
	case 0:
		return blockedServicesFuzzOperation{
			jsonResponse: true,
			method:       http.MethodGet,
			name:         blockedServicesAllOperation,
			path:         "/api/control/blocked_services/all",
		}
	case 1:
		return blockedServicesFuzzOperation{
			jsonResponse: true,
			method:       http.MethodGet,
			name:         blockedServicesScheduleOperation,
			path:         "/api/control/blocked_services/get",
		}
	default:
		return blockedServicesFuzzOperation{
			jsonResponse: false,
			method:       http.MethodPut,
			name:         blockedServicesScheduleUpdateOperation,
			path:         "/api/control/blocked_services/update",
		}
	}
}

// blockedServicesFuzzHTTPResponse creates the selected deterministic HTTP response.
func blockedServicesFuzzHTTPResponse(
	request *http.Request,
	state *blockedServicesFuzzState,
) *http.Response {
	statusCode := http.StatusOK
	contentType := testResponseMediaType

	switch state.mode {
	case blockedServicesFuzzOpaque:
		contentType = blockedServicesFuzzTextMediaType
	case blockedServicesFuzzStatus:
		statusCode = http.StatusUnprocessableEntity
		contentType = blockedServicesFuzzTextMediaType
	case blockedServicesFuzzRedirect:
		statusCode = http.StatusTemporaryRedirect
		contentType = blockedServicesFuzzTextMediaType
	case blockedServicesFuzzTooLarge, blockedServicesFuzzJSON:
	default:
		contentType = testResponseMediaType
	}

	response := fuzzHTTPResponse(request, statusCode, contentType, state.response)
	if state.mode == blockedServicesFuzzRedirect {
		response.Header.Set("Location", blockedServicesFuzzRedirectLocation)
	}

	return response
}

// requireBlockedServicesFuzzRequest verifies request method, path, and body presence.
func requireBlockedServicesFuzzRequest(t *testing.T, state *blockedServicesFuzzState) {
	t.Helper()

	require.Len(t, state.captures, 1)

	capture := state.captures[0]
	assert.Equal(t, state.operation.method, capture.method)
	assert.Equal(t, state.operation.path, capture.path)
	assert.Empty(t, capture.query)

	if state.operation.jsonResponse {
		assert.Empty(t, capture.contentType)
		assert.Empty(t, capture.body)

		return
	}

	assert.Equal(t, testResponseMediaType, capture.contentType)
	assert.NotEmpty(t, capture.body)
	requireFuzzJSONBody(t, capture)
}

// requireBlockedServicesCatalogFuzzResult verifies catalog success invariants or structured failure.
func requireBlockedServicesCatalogFuzzResult(
	t *testing.T,
	state *blockedServicesFuzzState,
	catalog *BlockedServicesAll,
	err error,
) {
	t.Helper()

	if err == nil {
		require.NotNil(t, catalog)
		assert.NotNil(t, catalog.BlockedServices)
		assert.NotNil(t, catalog.Groups)
	} else {
		assert.Nil(t, catalog)
	}

	requireBlockedServicesFuzzOutcome(t, state, err)
}

// requireBlockedServicesScheduleFuzzResult verifies schedule success or structured failure.
func requireBlockedServicesScheduleFuzzResult(
	t *testing.T,
	state *blockedServicesFuzzState,
	schedule *BlockedServicesSchedule,
	err error,
) {
	t.Helper()

	if err == nil {
		require.NotNil(t, schedule)
	} else {
		assert.Nil(t, schedule)
	}

	requireBlockedServicesFuzzOutcome(t, state, err)
}

// requireBlockedServicesUpdateFuzzResult verifies body-agnostic update outcomes.
func requireBlockedServicesUpdateFuzzResult(
	t *testing.T,
	state *blockedServicesFuzzState,
	err error,
) {
	t.Helper()
	requireBlockedServicesFuzzOutcome(t, state, err)
}

// requireBlockedServicesFuzzOutcome verifies the structured error for the selected response mode.
func requireBlockedServicesFuzzOutcome(
	t *testing.T,
	state *blockedServicesFuzzState,
	err error,
) {
	t.Helper()

	if err == nil {
		requireBlockedServicesFuzzSuccess(t, state)

		return
	}
	if state.mode == blockedServicesFuzzOpaque && !state.operation.jsonResponse {
		require.NoError(t, err)

		return
	}

	clientErr := requireFuzzError(
		t,
		err,
		blockedServicesFuzzErrorKind(state),
		state.operation.name,
		state.operation.method,
	)
	requireBlockedServicesFuzzMetadata(t, state, clientErr)
}

// requireBlockedServicesFuzzSuccess verifies the successful mode for one response policy.
func requireBlockedServicesFuzzSuccess(t *testing.T, state *blockedServicesFuzzState) {
	t.Helper()

	if state.operation.jsonResponse {
		assert.Equal(t, blockedServicesFuzzJSON, state.mode)

		return
	}

	assert.Contains(
		t,
		[]byte{blockedServicesFuzzJSON, blockedServicesFuzzOpaque},
		state.mode,
	)
}

// blockedServicesFuzzErrorKind classifies the expected error for one response policy.
func blockedServicesFuzzErrorKind(state *blockedServicesFuzzState) ErrorKind {
	switch state.mode {
	case blockedServicesFuzzOpaque:
		return ErrorKindContentType
	case blockedServicesFuzzStatus:
		return ErrorKindStatus
	case blockedServicesFuzzRedirect:
		return ErrorKindRedirect
	case blockedServicesFuzzTooLarge:
		return ErrorKindResponseTooLarge
	case blockedServicesFuzzJSON:
		return ErrorKindJSON
	default:
		return ""
	}
}

// requireBlockedServicesFuzzMetadata verifies mode-specific structured error fields.
func requireBlockedServicesFuzzMetadata(
	t *testing.T,
	state *blockedServicesFuzzState,
	clientErr *Error,
) {
	t.Helper()

	switch state.mode {
	case blockedServicesFuzzStatus:
		assert.Equal(t, http.StatusUnprocessableEntity, clientErr.StatusCode)
		assert.Equal(t, state.response, clientErr.Body)
		assert.Equal(t, blockedServicesFuzzTextMediaType, clientErr.ContentType)
	case blockedServicesFuzzRedirect:
		assert.Equal(t, blockedServicesFuzzRedirectLocation, clientErr.Location)
	case blockedServicesFuzzTooLarge:
		assert.Equal(t, state.limit, clientErr.Limit)
		assert.Equal(t, http.StatusOK, clientErr.StatusCode)
		assert.Equal(t, testResponseMediaType, clientErr.ContentType)
	default:
		require.Error(t, clientErr.Err)
	}
}

// exerciseBlockedServicesRequestFuzz checks one bounded schedule-update request.
func exerciseBlockedServicesRequestFuzz(t *testing.T, data []byte) {
	t.Helper()

	if len(data) > blockedServicesFuzzMaxRequestBytes || !utf8.Valid(data) {
		return
	}

	schedule, encodingFails := buildBlockedServicesFuzzSchedule(data)
	state := newBlockedServicesFuzzState(t, 2, blockedServicesFuzzJSON, []byte(`{}`))
	err := state.client.BlockedServicesScheduleUpdate(t.Context(), schedule)
	if encodingFails {
		clientErr := requireFuzzError(
			t,
			err,
			ErrorKindJSON,
			blockedServicesScheduleUpdateOperation,
			http.MethodPut,
		)
		require.Error(t, clientErr.Err)
		assert.Empty(t, state.captures)

		return
	}

	require.NoError(t, err)
	requireBlockedServicesFuzzRequest(t, state)
	requireBlockedServicesScheduleJSON(t, state.captures[0], schedule)
}

// buildBlockedServicesFuzzSchedule builds a bounded presence-sensitive update model.
func buildBlockedServicesFuzzSchedule(data []byte) (BlockedServicesSchedule, bool) {
	schedule := buildBlockedServicesFuzzBase(data)
	days := buildBlockedServicesFuzzDays(data)

	schedule.Schedule = mergeBlockedServicesFuzzDays(schedule.Schedule, days)

	return schedule, blockedServicesFuzzEncodingFails(schedule.Schedule)
}

// buildBlockedServicesFuzzBase builds the presence-sensitive top-level schedule fields.
func buildBlockedServicesFuzzBase(data []byte) BlockedServicesSchedule {
	return BlockedServicesSchedule{
		IDs:      buildBlockedServicesFuzzIDs(data),
		Schedule: buildBlockedServicesFuzzScheduleModel(data),
	}
}

// buildBlockedServicesFuzzIDs builds the optional service identifier list.
func buildBlockedServicesFuzzIDs(data []byte) *[]string {
	if !blockedServicesFuzzBit(data, 0, 1) {
		return nil
	}

	ids := []string{}
	if blockedServicesFuzzBit(data, 0, 4) {
		ids = append(ids, string(data))
	}

	return &ids
}

// buildBlockedServicesFuzzScheduleModel builds the optional nested schedule.
func buildBlockedServicesFuzzScheduleModel(data []byte) *Schedule {
	if !blockedServicesFuzzBit(data, 0, 0) {
		return nil
	}

	schedule := &Schedule{}
	if blockedServicesFuzzBit(data, 0, 2) {
		timeZone := string(data)

		schedule.TimeZone = &timeZone
	}

	return schedule
}

// buildBlockedServicesFuzzDays builds all optional daily ranges.
func buildBlockedServicesFuzzDays(data []byte) [7]*DayRange {
	var days [7]*DayRange

	for index := range days {
		days[index] = buildBlockedServicesFuzzDay(data, index)
	}

	return days
}

// buildBlockedServicesFuzzDay builds one optional daily range.
func buildBlockedServicesFuzzDay(data []byte, index int) *DayRange {
	if !blockedServicesFuzzBit(data, 1, index) {
		return nil
	}

	day := &DayRange{}
	if blockedServicesFuzzBit(data, 2, 0) {
		if blockedServicesFuzzBit(data, 0, 3) && index == 0 {
			day.Start = new(math.NaN())
		} else {
			day.Start = new(blockedServicesFuzzNumber(data))
		}
	}
	if blockedServicesFuzzBit(data, 2, 1) {
		day.End = new(blockedServicesFuzzNumber(data) + 1)
	}

	return day
}

// blockedServicesFuzzNumber returns a finite schedule time value.
func blockedServicesFuzzNumber(data []byte) float64 {
	if len(data) <= 3 {
		return 0
	}

	return float64(data[3])
}

// blockedServicesFuzzEncodingFails reports the intentionally invalid generated model.
func blockedServicesFuzzEncodingFails(schedule *Schedule) bool {
	return schedule != nil &&
		schedule.Sun != nil &&
		schedule.Sun.Start != nil &&
		math.IsNaN(*schedule.Sun.Start)
}

// mergeBlockedServicesFuzzDays assigns generated day ranges to one schedule.
func mergeBlockedServicesFuzzDays(schedule *Schedule, days [7]*DayRange) *Schedule {
	if schedule == nil {
		return nil
	}

	schedule.Sun = days[0]
	schedule.Mon = days[1]
	schedule.Tue = days[2]
	schedule.Wed = days[3]
	schedule.Thu = days[4]
	schedule.Fri = days[5]
	schedule.Sat = days[6]

	return schedule
}

// blockedServicesFuzzBit reports whether one bounded input byte contains a bit.
func blockedServicesFuzzBit(data []byte, index, bit int) bool {
	return len(data) > index && data[index]&(1<<bit) != 0
}

// requireBlockedServicesScheduleJSON verifies exact update request property presence.
func requireBlockedServicesScheduleJSON(
	t *testing.T,
	capture fuzzRequestCapture,
	schedule BlockedServicesSchedule,
) {
	t.Helper()

	var fields map[string]any

	require.NoError(t, json.Unmarshal(capture.body, &fields))
	requireBlockedServicesFuzzFields(t, fields, map[string]bool{
		adguardTestScheduleField: schedule.Schedule != nil,
		adguardTestIDsField:      schedule.IDs != nil,
	})

	if schedule.Schedule == nil {
		return
	}

	scheduleFields, ok := fields["schedule"].(map[string]any)
	require.True(t, ok)
	requireBlockedServicesFuzzFields(t, scheduleFields, map[string]bool{
		"time_zone": schedule.Schedule.TimeZone != nil,
		"sun":       schedule.Schedule.Sun != nil,
		"mon":       schedule.Schedule.Mon != nil,
		"tue":       schedule.Schedule.Tue != nil,
		"wed":       schedule.Schedule.Wed != nil,
		"thu":       schedule.Schedule.Thu != nil,
		"fri":       schedule.Schedule.Fri != nil,
		"sat":       schedule.Schedule.Sat != nil,
	})
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "sun", schedule.Schedule.Sun)
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "mon", schedule.Schedule.Mon)
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "tue", schedule.Schedule.Tue)
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "wed", schedule.Schedule.Wed)
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "thu", schedule.Schedule.Thu)
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "fri", schedule.Schedule.Fri)
	requireBlockedServicesFuzzDayJSON(t, scheduleFields, "sat", schedule.Schedule.Sat)
}

// requireBlockedServicesFuzzDayJSON verifies one optional daily range object.
func requireBlockedServicesFuzzDayJSON(
	t *testing.T,
	scheduleFields map[string]any,
	name string,
	day *DayRange,
) {
	t.Helper()

	if day == nil {
		return
	}

	fields, ok := scheduleFields[name].(map[string]any)
	require.True(t, ok)
	requireBlockedServicesFuzzFields(t, fields, map[string]bool{
		"start": day.Start != nil,
		"end":   day.End != nil,
	})
}

// requireBlockedServicesFuzzFields verifies exact key presence in one JSON object.
func requireBlockedServicesFuzzFields(
	t *testing.T,
	fields map[string]any,
	expected map[string]bool,
) {
	t.Helper()

	expectedCount := 0

	for key, present := range expected {
		if present {
			expectedCount++
		}

		_, actual := fields[key]
		require.Equal(t, present, actual, "JSON field %q presence", key)
	}

	require.Len(t, fields, expectedCount)
}
