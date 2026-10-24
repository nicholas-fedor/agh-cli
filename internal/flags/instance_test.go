// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestInstanceListFlagsBindPublishesFlag verifies the published list flag.
func TestInstanceListFlagsBindPublishesFlag(t *testing.T) {
	t.Parallel()

	values := new(InstanceListFlags)
	fs := parsedFlags(t, values.Bind, "-a")

	assertFlag(t, fs, "all", "a", "false", "show all instances")
	assert.True(t, values.All)
}

// TestInstanceAddFlagsBindPublishesFlag verifies the published add flag and its
// HTTPS default.
func TestInstanceAddFlagsBindPublishesFlag(t *testing.T) {
	t.Parallel()

	values := new(InstanceAddFlags)
	fs := parsedFlags(t, values.Bind)

	assertFlag(t, fs, "scheme", "s", "https", "HTTP scheme")
	assert.Equal(t, "https", values.Scheme)
}
