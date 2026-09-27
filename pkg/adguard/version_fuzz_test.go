// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzVersionResponseBodies verifies the version response schema stays structured and bounded.
func FuzzVersionResponseBodies(f *testing.F) {
	addFuzzResponseSeeds(f)

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > fuzzResponseMaxBytes {
			body = body[:fuzzResponseMaxBytes]
		}

		exerciseVersionResponseFuzz(t, body)
	})
}

// FuzzVersionRequestValues verifies every version request value stays structured.
func FuzzVersionRequestValues(f *testing.F) {
	addFuzzRequestSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzRequestMaxBytes {
			data = data[:fuzzRequestMaxBytes]
		}

		exerciseVersionRequestFuzz(t, data)
	})
}

// exerciseVersionResponseFuzz validates version response decoding and conversion.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - body: The bounded JSON response body.
func exerciseVersionResponseFuzz(t *testing.T, body []byte) {
	t.Helper()

	var wire versionInfoWire

	err := decodeGlobalJSON(
		operationGetVersionInfo,
		http.MethodPost,
		body,
		&wire,
	)
	if err != nil {
		assertFuzzResponseError(t, err, operationGetVersionInfo, http.MethodPost)

		return
	}

	versionInfo, validationErr := versionInfoFromWire(&wire)
	if validationErr != nil {
		assertFuzzResponseError(
			t,
			globalJSONError(operationGetVersionInfo, http.MethodPost, validationErr),
			operationGetVersionInfo,
			http.MethodPost,
		)

		return
	}

	require.NotNil(t, versionInfo)
}

// exerciseVersionRequestFuzz exercises the version information request.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - data: The bounded encoded request values.
func exerciseVersionRequestFuzz(t *testing.T, data []byte) {
	t.Helper()

	client := newFuzzRequestClient(t)

	var recheckNow *bool

	if fuzzRequestFlag(data, fuzzRequestOmitRecheckNow) == 0 {
		recheckNow = new(fuzzRequestBoolean(data, fuzzRequestRecheckNowBit))
	}

	versionInfo, err := client.GetVersionInfo(t.Context(), recheckNow)
	require.NoError(t, err)
	require.NotNil(t, versionInfo)
}
