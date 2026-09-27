// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzProfileResponseBodies verifies the profile response schema stays structured and bounded.
func FuzzProfileResponseBodies(f *testing.F) {
	addFuzzResponseSeeds(f)

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > fuzzResponseMaxBytes {
			body = body[:fuzzResponseMaxBytes]
		}

		exerciseProfileResponseFuzz(t, body)
	})
}

// FuzzProfileRequestValues verifies every profile request value stays structured.
func FuzzProfileRequestValues(f *testing.F) {
	addFuzzRequestSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzRequestMaxBytes {
			data = data[:fuzzRequestMaxBytes]
		}

		exerciseProfileRequestFuzz(t, data)
	})
}

// exerciseProfileResponseFuzz validates profile response decoding and conversion.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - body: The bounded JSON response body.
func exerciseProfileResponseFuzz(t *testing.T, body []byte) {
	t.Helper()

	var wire profileWire

	err := decodeGlobalJSON(operationGetProfile, http.MethodGet, body, &wire)
	if err != nil {
		assertFuzzResponseError(t, err, operationGetProfile, http.MethodGet)

		return
	}

	profile, validationErr := profileFromWire(wire)
	if validationErr != nil {
		assertFuzzResponseError(
			t,
			globalJSONError(operationGetProfile, http.MethodGet, validationErr),
			operationGetProfile,
			http.MethodGet,
		)

		return
	}

	require.NotNil(t, profile)
}

// exerciseProfileRequestFuzz exercises profile update and retrieval requests.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - data: The bounded encoded request values.
func exerciseProfileRequestFuzz(t *testing.T, data []byte) {
	t.Helper()

	client := newFuzzRequestClient(t)

	err := client.UpdateProfile(t.Context(), Profile{
		Name:     fuzzRequestString(data, fuzzRequestProfileName),
		Language: fuzzRequestString(data, fuzzRequestLanguage),
		Theme:    fuzzRequestString(data, fuzzRequestTheme),
	})
	assertFuzzRequestError(t, err, operationUpdateProfile, http.MethodPut)

	profile, err := client.GetProfile(t.Context())
	require.NoError(t, err)
	require.NotNil(t, profile)
}
