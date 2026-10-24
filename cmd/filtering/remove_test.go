// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunFilteringRemoveURLSendsLocation verifies that remove-url sends the
// location to every selected instance in configuration order, and writes one
// result per instance to standard output.
func TestRunFilteringRemoveURLSendsLocation(t *testing.T) {
	t.Parallel()

	alpha := newFilteringRecorder(t, http.StatusOK, "")
	zulu := newFilteringRecorder(t, http.StatusOK, "")
	ctx := filteringCommandContext(t, alpha, zulu)

	run := runFiltering(ctx, t, filteringCommandRemoveURLName, filteringCommandAllFlagArg, filteringCommandFilterURL)

	require.NoError(t, run.err)

	expected := []filteringRequest{{
		Body:  map[string]any{"url": filteringCommandFilterURL, "whitelist": false},
		Route: "POST /control/filtering/remove_url",
	}}
	assert.Equal(t, expected, alpha.recorded())
	assert.Equal(t, expected, zulu.recorded())
	assert.Equal(t,
		"[alpha] Removed filter URL "+filteringCommandFilterURL+"\n"+
			"[zulu] Removed filter URL "+filteringCommandFilterURL+"\n",
		run.out)
	assert.Empty(t, run.errOut)
}
