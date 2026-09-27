// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// FuzzProtectionRequestValues verifies every protection request value stays structured.
func FuzzProtectionRequestValues(f *testing.F) {
	addFuzzRequestSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzRequestMaxBytes {
			data = data[:fuzzRequestMaxBytes]
		}

		exerciseProtectionRequestFuzz(t, data)
	})
}

// exerciseProtectionRequestFuzz exercises protection and cache-clear requests.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - data: The bounded encoded request values.
func exerciseProtectionRequestFuzz(t *testing.T, data []byte) {
	t.Helper()

	client := newFuzzRequestClient(t)

	var duration *uint64

	if fuzzRequestFlag(data, fuzzRequestOmitDuration) == 0 {
		durationValue := uint64(fuzzRequestNumber(data, fuzzRequestProtectionDuration))

		duration = new(durationValue)
	}

	err := client.SetProtection(t.Context(), ProtectionConfig{
		Enabled:  fuzzRequestBoolean(data, fuzzRequestProtectionEnabledBit),
		Duration: duration,
	})
	assertFuzzRequestError(t, err, operationSetProtection, http.MethodPost)

	require.NoError(t, client.ClearCache(t.Context()))
}
