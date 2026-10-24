// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunFilteringConfigSendsFlagValues verifies that config sends the enabled
// and interval flag values to the named instance only, and writes its result to
// standard output.
func TestRunFilteringConfigSendsFlagValues(t *testing.T) {
	t.Parallel()

	alpha := newFilteringRecorder(t, http.StatusOK, "")
	zulu := newFilteringRecorder(t, http.StatusOK, "")
	ctx := filteringCommandContext(t, alpha, zulu)

	run := runFiltering(ctx, t,
		filteringCommandConfigName,
		filteringCommandInstanceFlagArg, filteringCommandAlphaInstance,
		"--enabled=false",
		"--interval", "24",
	)

	require.NoError(t, run.err)
	assert.Equal(t, []filteringRequest{{
		Body:  map[string]any{"enabled": false, "interval": float64(24)},
		Route: "POST /control/filtering/config",
	}}, alpha.recorded())
	assert.Empty(t, zulu.recorded())
	assert.Equal(t, "[alpha] Filtering config updated: enabled=false, interval=24\n", run.out)
	assert.Empty(t, run.errOut)
}
