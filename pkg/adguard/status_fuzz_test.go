// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// statusFuzzMaxBodyBytes bounds JSON decoding work for each generated response.
const statusFuzzMaxBodyBytes = 16 << 10

// FuzzStatusResponse verifies bounded status payloads return valid values or structured errors.
func FuzzStatusResponse(f *testing.F) {
	addStatusFuzzSeeds(f)

	f.Fuzz(func(t *testing.T, body []byte) {
		exerciseStatusFuzzResponse(t, body)
	})
}

// addStatusFuzzSeeds registers deterministic status response fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addStatusFuzzSeeds(f *testing.F) {
	f.Helper()

	seeds := []string{
		`{
			"dns_addresses":["127.0.0.1","::1"],
			"dns_port":53,
			"http_port":3000,
			"language":"en",
			"protection_enabled":true,
			"protection_disabled_duration":0,
			"dhcp_available":false,
			"running":true,
			"version":"v0.107.52",
			"start_time":1700000000000,
			"future_field":{"ignored":true}
		}`,
		`{
			"dns_addresses":[],
			"dns_port":1,
			"http_port":65535,
			"language":"",
			"protection_enabled":false,
			"running":false,
			"version":""
		}`,
		`{
			"dns_addresses":null,
			"dns_port":53,
			"http_port":3000,
			"language":"en",
			"protection_enabled":true,
			"running":true,
			"version":"v0.107.52"
		}`,
		`{
			"dns_port":0,
			"http_port":3000,
			"language":"en",
			"protection_enabled":true,
			"running":true,
			"version":"v0.107.52"
		}`,
		`{
			"dns_addresses":["127.0.0.1"],
			"dns_port":65536,
			"http_port":3000,
			"language":"en",
			"protection_enabled":true,
			"running":true,
			"version":"v0.107.52"
		}`,
		globalFuzzDuplicateMemberJSON,
		`{"dns_addresses":`,
		testNullJSON,
		`{}`,
		``,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
}

// exerciseStatusFuzzResponse checks one bounded status response body.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - body: The generated JSON response body.
func exerciseStatusFuzzResponse(t *testing.T, body []byte) {
	t.Helper()

	if len(body) > statusFuzzMaxBodyBytes {
		body = body[:statusFuzzMaxBodyBytes]
	}

	status, err := decodeServerStatus(body)
	if err != nil {
		assert.Nil(t, status)
		assertStatusFuzzError(t, err)

		return
	}

	require.NotNil(t, status)
	assert.NotNil(t, status.DNSAddresses)
	assert.NotZero(t, status.DNSPort)
	assert.NotZero(t, status.HTTPPort)
}

// assertStatusFuzzError verifies the complete structured status JSON error shape.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The structured error returned by status decoding.
func assertStatusFuzzError(t *testing.T, err *Error) {
	t.Helper()

	require.Error(t, err)
	assert.Equal(t, ErrorKindJSON, err.Kind)
	assert.Equal(t, string(ErrorKindStatus), err.Operation)
	assert.Equal(t, http.MethodGet, err.Method)
	assert.Zero(t, err.StatusCode)
	assert.Empty(t, err.Body)
	assert.Error(t, err.Err)
}
