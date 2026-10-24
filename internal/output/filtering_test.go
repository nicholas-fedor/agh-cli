// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/filtering"
)

// TestWriteFilteringStatusesSeparatesInstances verifies the subscription rows of
// both lists, the instance order, and the single blank line between tables.
func TestWriteFilteringStatusesSeparatesInstances(t *testing.T) {
	t.Parallel()

	filters := []filtering.Subscription{
		{Enabled: false, Name: "filters", RulesCount: 7, URL: "https://filters.example/list.txt"},
	}
	allowlists := []filtering.Subscription{
		{Enabled: true, Name: "allow", RulesCount: 2, URL: "https://allow.example/list.txt"},
	}

	var rendered bytes.Buffer

	err := WriteFilteringStatuses(&rendered, []app.FilteringStatusResult{
		{Filters: &filters, WhitelistFilters: &allowlists, Instance: "alpha", InstanceCount: 2},
		{Filters: nil, WhitelistFilters: nil, Instance: "zulu", InstanceCount: 2},
	})

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(rendered.String(), "Instance: alpha\n"))
	assert.Contains(t, rendered.String(), "alpha     filters  disabled  7      https://filters.example/list.txt")
	assert.Contains(t, rendered.String(), "alpha     allow    enabled   2      https://allow.example/list.txt")
	assert.Contains(t, rendered.String(), "\n\nInstance: zulu\n")
	assert.NotContains(t, rendered.String(), "\n\n\n")
}

// TestWriteFilteringStatusesReportsWriteFailures verifies that a table that
// cannot be written names its instance.
func TestWriteFilteringStatusesReportsWriteFailures(t *testing.T) {
	t.Parallel()

	err := WriteFilteringStatuses(errorWriter{err: errWriteFailed}, []app.FilteringStatusResult{
		{Filters: nil, WhitelistFilters: nil, Instance: "alpha", InstanceCount: 2},
	})

	require.ErrorIs(t, err, errWriteFailed)
	assert.Contains(t, err.Error(), `write instance "alpha" filtering status header`)
}
