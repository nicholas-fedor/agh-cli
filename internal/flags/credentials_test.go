// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialFlagsBindPublishFlags verifies the published flags of the
// credential commands.
func TestCredentialFlagsBindPublishFlags(t *testing.T) {
	t.Parallel()

	report := parsedFlags(t, new(ReportFlags).Bind)
	assertFlag(t, report, "json", "", "false", "render the report as JSON")

	migrate := parsedFlags(t, new(MigrateFlags).Bind)
	assertFlag(t, migrate, "dry-run", "", "false",
		"report the change without writing to the store or the configuration")

	set := parsedFlags(t, new(PasswordSetFlags).Bind)
	assertFlag(t, set, "key", "", "", "credential key, defaults to the instance name")
	assertFlag(t, set, "yes", "y", "false", "store the credential without asking for confirmation")

	clearFlags := parsedFlags(t, new(PasswordClearFlags).Bind)
	assertFlag(t, clearFlags, "all", "", "false", "remove every credential of the configured service")
	assertFlag(t, clearFlags, "yes", "y", "false", "remove the credential without asking for confirmation")
}

// TestPasswordClearFlagsValidateSelection verifies that a clear request names
// exactly one of an instance and the whole service.
func TestPasswordClearFlagsValidateSelection(t *testing.T) {
	t.Parallel()

	service := &PasswordClearFlags{All: true, Yes: false}
	instance := &PasswordClearFlags{All: false, Yes: false}

	require.NoError(t, service.Validate(nil))
	require.NoError(t, instance.Validate([]string{"alpha"}))

	err := service.Validate([]string{"alpha"})
	require.ErrorIs(t, err, ErrInvalidSelection)
	assert.Contains(t, err.Error(), "--all and an instance name are mutually exclusive")

	require.ErrorIs(t, instance.Validate(nil), ErrInvalidSelection)
}
