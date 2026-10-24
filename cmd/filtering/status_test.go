// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// filteringStatusResponse is a filtering status reply with one subscription.
const filteringStatusResponse = `{"enabled":true,"interval":24,"filters":[{"enabled":true,"id":1,` +
	`"last_updated":"2026-01-01T00:00:00Z","name":"Example list","rules_count":5,` +
	`"url":"https://filters.example/list.txt"}],"whitelist_filters":[],"user_rules":[]}`

// TestRunFilteringStatusWritesSelectedInstance verifies that status reads only
// the named instance and writes its subscription table to standard output.
func TestRunFilteringStatusWritesSelectedInstance(t *testing.T) {
	t.Parallel()

	alpha := newFilteringRecorder(t, http.StatusOK, filteringStatusResponse)
	zulu := newFilteringRecorder(t, http.StatusOK, filteringStatusResponse)
	ctx := filteringCommandContext(t, alpha, zulu)

	run := runFiltering(ctx, t,
		filteringCommandStatusName,
		filteringCommandInstanceFlagArg, filteringCommandAlphaInstance,
	)

	require.NoError(t, run.err)
	assert.Equal(t, []filteringRequest{{Body: nil, Route: "GET /control/filtering/status"}}, alpha.recorded())
	assert.Empty(t, zulu.recorded())
	assert.Contains(t, run.out, "INSTANCE  NAME")
	assert.Contains(t, run.out, filteringCommandFilterName)
	assert.Contains(t, run.out, filteringCommandFilterURL)
	assert.NotContains(t, run.out, "Instance: ")
	assert.Empty(t, run.errOut)
}

// TestRunFilteringStatusReportsPartialFailure verifies that status over every
// instance writes the table of each instance that answered, and that the
// failure of another instance keeps its structured error and the command's
// context.
func TestRunFilteringStatusReportsPartialFailure(t *testing.T) {
	t.Parallel()

	alpha := newFilteringRecorder(t, http.StatusOK, filteringStatusResponse)
	zulu := newFilteringRecorder(t, http.StatusInternalServerError, "")
	ctx := filteringCommandContext(t, alpha, zulu)

	run := runFiltering(ctx, t, filteringCommandStatusName, filteringCommandAllFlagArg)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "get filtering status")
	assert.Contains(t, run.err.Error(), filteringCommandZuluInstance)

	gotErr, ok := errors.AsType[*adguard.Error](run.err)
	require.True(t, ok)
	assert.Equal(t, adguard.ErrorKindStatus, gotErr.Kind)

	assert.Contains(t, run.out, "Instance: alpha")
	assert.Contains(t, run.out, filteringCommandFilterURL)
	assert.NotContains(t, run.out, "Instance: zulu")
}
