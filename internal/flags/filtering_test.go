// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFilteringAddURLFlagsBindPublishesFlags verifies the published add-url
// flags and an explicit false allowlist value.
func TestFilteringAddURLFlagsBindPublishesFlags(t *testing.T) {
	t.Parallel()

	values := new(FilteringAddURLFlags)
	fs := parsedFlags(t, values.Bind, "--whitelist=false", "--all")

	assertFlag(t, fs, "whitelist", "w", "false", "add to whitelist")
	assert.False(t, values.Whitelist)
	assert.True(t, values.Selection().All)
}

// TestFilteringConfigFlagsBindPublishesFlags verifies the published config flags
// and that explicit false and zero values are kept.
func TestFilteringConfigFlagsBindPublishesFlags(t *testing.T) {
	t.Parallel()

	values := new(FilteringConfigFlags)
	fs := parsedFlags(t, values.Bind, "--enabled=false", "--interval=0")

	assertFlag(t, fs, "enabled", "e", "true", "enable filtering")
	assertFlag(t, fs, "interval", "n", "0", "update interval hours")
	assert.False(t, values.Enabled)
	assert.Zero(t, values.IntervalHours())
}

// TestFilteringConfigFlagsIntervalHoursWidensValue verifies the interval reaches
// the use case unchanged.
func TestFilteringConfigFlagsIntervalHoursWidensValue(t *testing.T) {
	t.Parallel()

	values := new(FilteringConfigFlags)
	parsedFlags(t, values.Bind, "-n", "72")

	assert.Equal(t, int64(72), values.IntervalHours())
}
