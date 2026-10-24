// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRunFilteringAddURLSendsArguments verifies that add-url sends the name,
// the location, and the list kind to the named instance only, and writes its
// result to standard output.
func TestRunFilteringAddURLSendsArguments(t *testing.T) {
	t.Parallel()

	alpha := newFilteringRecorder(t, http.StatusOK, "")
	zulu := newFilteringRecorder(t, http.StatusOK, "")
	ctx := filteringCommandContext(t, alpha, zulu)

	run := runFiltering(ctx, t,
		filteringCommandAddURLName,
		filteringCommandInstanceFlagArg, filteringCommandAlphaInstance,
		"--whitelist",
		filteringCommandFilterName,
		filteringCommandFilterURL,
	)

	require.NoError(t, run.err)
	assert.Equal(t, []filteringRequest{{
		Body: map[string]any{
			"name":      filteringCommandFilterName,
			"url":       filteringCommandFilterURL,
			"whitelist": true,
		},
		Route: "POST /control/filtering/add_url",
	}}, alpha.recorded())
	assert.Empty(t, zulu.recorded())
	assert.Equal(t, "[alpha] Added filter URL "+filteringCommandFilterName+"\n", run.out)
	assert.Empty(t, run.errOut)
}

// TestRunFilteringAddURLRequiresNameAndURL verifies the published argument
// arity, checked before any instance is contacted.
func TestRunFilteringAddURLRequiresNameAndURL(t *testing.T) {
	t.Parallel()

	alpha := newFilteringRecorder(t, http.StatusOK, "")
	zulu := newFilteringRecorder(t, http.StatusOK, "")
	ctx := filteringCommandContext(t, alpha, zulu)

	run := runFiltering(ctx, t, filteringCommandAddURLName, filteringCommandAllFlagArg, filteringCommandFilterURL)

	require.Error(t, run.err)
	assert.Empty(t, alpha.recorded())
	assert.Empty(t, zulu.recorded())
}
