// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mobileConfigFuzzState contains one bounded mobile-configuration exercise.
type mobileConfigFuzzState struct {
	// request is the fuzz-derived mobile configuration request.
	request MobileConfigRequest
	// validationErr is the local request-validation result.
	validationErr error
	// responseData is the bounded opaque response body.
	responseData []byte
	// captured is the latest request observed by the deterministic transport.
	captured fuzzRequestCapture
	// client performs mobile configuration operations without network access.
	client *Client
	// expectedOperation is the selected public operation name.
	expectedOperation string
	// expectedPath is the selected public endpoint path.
	expectedPath string
	// statusCode is the deterministic HTTP response status.
	statusCode int
	// limit is the deterministic response body limit.
	limit int64
	// called reports whether the deterministic transport received a request.
	called bool
}

// mobileConfigFuzzOperationSpec identifies one selected public operation.
type mobileConfigFuzzOperationSpec struct {
	// name is the selected client operation name.
	name string
	// path is the selected endpoint path.
	path string
}

const (
	// Request fuzzing includes the oversized-host boundary.
	mobileConfigFuzzMaxHostBytes = mobileConfigMaxHostLength + 1
	// Request fuzzing bounds encoded client identifier work.
	mobileConfigFuzzMaxClientIDBytes = 256
	// Response fuzzing bounds opaque body handling.
	mobileConfigFuzzMaxResponseBytes = 4 << 10
)

// FuzzMobileConfigRequestResponse verifies bounded mobile request validation and binary responses.
func FuzzMobileConfigRequestResponse(f *testing.F) {
	f.Add(byte(0), byte(0), "dns.example", "device/1", []byte{0x00})
	f.Add(byte(1), byte(1), "dns.example", "", []byte{})
	f.Add(byte(0), byte(2), "dns.example", "device/2", []byte("x"))
	f.Add(byte(1), byte(3), "dns.example", "device/3", []byte{0x00, 0xff, 0x01})
	f.Add(byte(0), byte(4), "", "device/4", []byte("invalid host"))
	f.Add(byte(1), byte(0), "   ", "device/5", []byte("blank host"))
	f.Add(
		byte(0),
		byte(2),
		strings.Repeat("a", mobileConfigFuzzMaxHostBytes),
		"device/6",
		[]byte("oversized host"),
	)

	f.Fuzz(func(
		t *testing.T,
		operation byte,
		status byte,
		host string,
		clientID string,
		responseData []byte,
	) {
		exerciseMobileConfigFuzz(t, operation, status, host, clientID, responseData)
	})
}

// exerciseMobileConfigFuzz exercises one bounded mobile request and response pair.
//
// Parameters:
//   - operation: The selector for the DoH or DoT public operation.
//   - status: The selector for the deterministic HTTP response status.
//   - host: The fuzz-derived request host.
//   - clientID: The fuzz-derived optional client identifier.
//   - responseData: The fuzz-derived opaque response bytes.
func exerciseMobileConfigFuzz(
	t *testing.T,
	operation byte,
	status byte,
	host string,
	clientID string,
	responseData []byte,
) {
	t.Helper()

	host = host[:min(len(host), mobileConfigFuzzMaxHostBytes)]
	clientID = clientID[:min(len(clientID), mobileConfigFuzzMaxClientIDBytes)]
	responseData = boundedFuzzInput(responseData, mobileConfigFuzzMaxResponseBytes)

	state := newMobileConfigFuzzState(t, operation, status, host, clientID, responseData)
	artifact, err := downloadMobileConfigFuzz(t, state)

	if state.validationErr != nil {
		requireMobileConfigInvalidRequest(t, state, artifact, err)

		return
	}

	requireMobileConfigRequest(t, state)
	requireMobileConfigResponse(t, state, artifact, err)
}

// newMobileConfigFuzzState creates an offline client and deterministic response fixture.
//
// Parameters:
//   - operationSelector: The selector for the DoH or DoT public operation.
//   - status: The selector for the deterministic HTTP response status.
//   - host: The bounded request host.
//   - clientID: The bounded optional client identifier.
//   - responseData: The bounded opaque response body.
//
// Returns:
//   - state: The configured mobile configuration fuzz state.
func newMobileConfigFuzzState(
	t *testing.T,
	operationSelector byte,
	status byte,
	host string,
	clientID string,
	responseData []byte,
) *mobileConfigFuzzState {
	t.Helper()

	var clientIDValue *string

	if clientID != "" {
		clientIDValue = &clientID
	}

	request := MobileConfigRequest{Host: host, ClientID: clientIDValue}
	operation := mobileConfigFuzzOperation(operationSelector)
	state := &mobileConfigFuzzState{
		request:           request,
		validationErr:     validateMobileConfigRequest(request),
		responseData:      responseData,
		captured:          fuzzRequestCapture{},
		client:            nil,
		expectedOperation: operation.name,
		expectedPath:      operation.path,
		statusCode:        fuzzMobileConfigStatus(status),
		limit:             max(int64(1), int64(len(responseData))/2),
		called:            false,
	}
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		state.called = true

		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		state.captured = capture

		return fuzzHTTPResponse(
			request,
			state.statusCode,
			mobileConfigAccept,
			state.responseData,
		), nil
	})

	state.client = newFuzzClient(t, transport, state.limit)

	return state
}

// mobileConfigFuzzOperation selects one public mobile configuration operation.
//
// Parameters:
//   - selector: The bounded operation selector.
//
// Returns:
//   - operation: The selected public operation and endpoint.
func mobileConfigFuzzOperation(selector byte) mobileConfigFuzzOperationSpec {
	if selector%2 == 0 {
		return mobileConfigFuzzOperationSpec{
			name: mobileConfigDoHOperation,
			path: "/api/control/apple/doh.mobileconfig",
		}
	}

	return mobileConfigFuzzOperationSpec{
		name: mobileConfigDoTOperation,
		path: "/api/control/apple/dot.mobileconfig",
	}
}

// downloadMobileConfigFuzz invokes the selected public mobile configuration operation.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
//
// Returns:
//   - artifact: The bounded downloaded artifact.
//   - err: The structured public operation error, if any.
func downloadMobileConfigFuzz(
	t *testing.T,
	state *mobileConfigFuzzState,
) (Artifact, error) {
	t.Helper()

	if state.expectedOperation == mobileConfigDoHOperation {
		return state.client.DownloadDoH(t.Context(), state.request)
	}

	return state.client.DownloadDoT(t.Context(), state.request)
}

// requireMobileConfigInvalidRequest verifies local validation precedes transport.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
//   - artifact: The artifact returned by the public operation.
//   - err: The error returned by the public operation.
func requireMobileConfigInvalidRequest(
	t *testing.T,
	state *mobileConfigFuzzState,
	artifact Artifact,
	err error,
) {
	t.Helper()
	require.Error(t, state.validationErr)

	clientErr := requireFuzzError(
		t,
		err,
		ErrorKindRequest,
		state.expectedOperation,
		http.MethodGet,
	)
	require.EqualError(t, clientErr.Err, state.validationErr.Error())
	assert.Zero(t, clientErr.StatusCode)
	assert.False(t, state.called)
	assert.Empty(t, artifact.Data)
	assert.Empty(t, artifact.ContentType)
}

// requireMobileConfigRequest verifies the bounded request query contract.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
func requireMobileConfigRequest(t *testing.T, state *mobileConfigFuzzState) {
	t.Helper()
	require.True(t, state.called)
	assert.Equal(t, http.MethodGet, state.captured.method)
	assert.Equal(t, state.expectedPath, state.captured.path)
	assert.Empty(t, state.captured.contentType)
	assert.Empty(t, state.captured.body)

	query, err := url.ParseQuery(state.captured.query)
	require.NoError(t, err)
	assert.Equal(t, state.request.Host, query.Get("host"))

	if state.request.ClientID == nil {
		assert.NotContains(t, query, "client_id")
	} else {
		assert.Equal(t, *state.request.ClientID, query.Get("client_id"))
	}
}

// requireMobileConfigResponse verifies the bounded artifact-or-error contract.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
//   - artifact: The artifact returned by the public operation.
//   - err: The error returned by the public operation.
func requireMobileConfigResponse(
	t *testing.T,
	state *mobileConfigFuzzState,
	artifact Artifact,
	err error,
) {
	t.Helper()

	switch {
	case int64(len(state.responseData)) > state.limit:
		requireMobileConfigTooLarge(t, state, artifact, err)
	case state.statusCode < http.StatusOK || state.statusCode >= http.StatusMultipleChoices:
		requireMobileConfigStatusError(t, state, artifact, err)
	default:
		requireMobileConfigSuccess(t, state, artifact, err)
	}
}

// requireMobileConfigTooLarge verifies the bounded response failure.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
//   - artifact: The artifact returned by the public operation.
//   - err: The error returned by the public operation.
func requireMobileConfigTooLarge(
	t *testing.T,
	state *mobileConfigFuzzState,
	artifact Artifact,
	err error,
) {
	t.Helper()

	clientErr := requireFuzzError(
		t,
		err,
		ErrorKindResponseTooLarge,
		state.expectedOperation,
		http.MethodGet,
	)
	assert.Equal(t, state.limit, clientErr.Limit)
	assert.Equal(t, state.statusCode, clientErr.StatusCode)
	assert.Equal(t, mobileConfigAccept, clientErr.ContentType)
	assert.Empty(t, artifact.Data)
	assert.Empty(t, artifact.ContentType)
}

// requireMobileConfigStatusError verifies the non-success response contract.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
//   - artifact: The artifact returned by the public operation.
//   - err: The error returned by the public operation.
func requireMobileConfigStatusError(
	t *testing.T,
	state *mobileConfigFuzzState,
	artifact Artifact,
	err error,
) {
	t.Helper()

	clientErr := requireFuzzError(
		t,
		err,
		ErrorKindStatus,
		state.expectedOperation,
		http.MethodGet,
	)
	assert.Equal(t, state.statusCode, clientErr.StatusCode)
	assert.Equal(t, mobileConfigAccept, clientErr.ContentType)
	assert.Equal(t, state.responseData, clientErr.Body)
	assert.Empty(t, artifact.Data)
	assert.Empty(t, artifact.ContentType)
}

// requireMobileConfigSuccess verifies exact opaque response preservation.
//
// Parameters:
//   - state: The deterministic mobile configuration fuzz state.
//   - artifact: The artifact returned by the public operation.
//   - err: The error returned by the public operation.
func requireMobileConfigSuccess(
	t *testing.T,
	state *mobileConfigFuzzState,
	artifact Artifact,
	err error,
) {
	t.Helper()
	require.NoError(t, err)
	assert.Equal(t, mobileConfigAccept, artifact.ContentType)
	assert.Equal(t, state.responseData, artifact.Data)
	assert.LessOrEqual(t, int64(len(artifact.Data)), state.limit)
}

// fuzzMobileConfigStatus maps a fuzz byte to a deterministic HTTP status.
//
// Parameters:
//   - selector: The bounded status selector.
//
// Returns:
//   - statusCode: A success or non-success HTTP status code.
func fuzzMobileConfigStatus(selector byte) int {
	switch selector % 5 {
	case 0:
		return http.StatusOK
	case 1:
		return http.StatusNoContent
	case 2:
		return http.StatusBadRequest
	case 3:
		return http.StatusServiceUnavailable
	default:
		return http.StatusTooManyRequests
	}
}
