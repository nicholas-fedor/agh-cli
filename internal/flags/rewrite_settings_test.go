// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestRewriteSettingsFlagsBindPublishesFlags verifies the published settings
// flag and an explicit false value.
func TestRewriteSettingsFlagsBindPublishesFlags(t *testing.T) {
	t.Parallel()

	values := new(RewriteSettingsFlags)
	fs := parsedFlags(t, values.Bind, "--enabled=false", "-i", "alpha")

	assertFlag(t, fs, "enabled", "e", "true", "enable rewrites")
	assert.False(t, values.Enabled)
	assert.Equal(t, []string{"alpha"}, values.Selection().Names)
}
