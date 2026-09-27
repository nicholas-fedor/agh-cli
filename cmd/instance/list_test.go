// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	domaininstance "github.com/nicholas-fedor/agh-cli/internal/instance"
)

const (
	// InstanceCommandAlphaName identifies the alpha command test instance.
	instanceCommandAlphaName = "alpha"
	// InstanceCommandDefaultName identifies the default command test instance.
	instanceCommandDefaultName = "default"
	// InstanceCommandZuluName identifies the zulu command test instance.
	instanceCommandZuluName = "zulu"
	// InstanceCommandHostKey is the raw command test host key.
	instanceCommandHostKey = "host"
	// InstanceCommandAlphaHost identifies the alpha command test host.
	instanceCommandAlphaHost = "command-alpha.example.com"
	// InstanceCommandDefaultHost identifies the default command test host.
	instanceCommandDefaultHost = "command-default.example.com"
	// InstanceCommandZuluHost identifies the zulu command test host.
	instanceCommandZuluHost = "command-zulu.example.com"
	// InstanceCommandHTTPScheme identifies a valid explicit transport scheme.
	instanceCommandHTTPScheme = "https"
)

// TestRunInstanceListWritesResolvedNamesInOrder verifies thin command output wiring.
func TestRunInstanceListWritesResolvedNamesInOrder(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	viper.Set("instances", map[string]any{
		instanceCommandZuluName: map[string]any{
			instanceCommandHostKey: instanceCommandZuluHost,
		},
		instanceCommandDefaultName: map[string]any{
			instanceCommandHostKey: instanceCommandDefaultHost,
		},
		instanceCommandAlphaName: map[string]any{
			instanceCommandHostKey: instanceCommandAlphaHost,
		},
	})

	run := runInstanceCommand(t, []string{InstanceListName, InstanceAllFlag})

	require.NoError(t, run.err)
	assert.Equal(t, "alpha\ndefault\nzulu\n", run.out)
}

// TestRunInstanceListPreservesResolutionErrors verifies command error forwarding.
func TestRunInstanceListPreservesResolutionErrors(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	viper.Set("instances", map[string]any{
		instanceCommandDefaultName: map[string]any{
			"scheme": instanceCommandHTTPScheme,
		},
	})

	run := runInstanceCommand(t, []string{InstanceListName})

	require.ErrorIs(t, run.err, domaininstance.ErrMissingHost)
	assert.NotContains(t, run.out, instanceCommandDefaultName)
}

// TestRunInstanceListRejectsInvalidInstanceMapping verifies that an instance
// stanza which is not a mapping is reported by the command instead of being
// skipped, so a mistyped configuration never lists a partial catalog.
func TestRunInstanceListRejectsInvalidInstanceMapping(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	viper.Set("instances", map[string]any{
		instanceCommandDefaultName: instanceCommandHTTPScheme,
	})

	run := runInstanceCommand(t, []string{InstanceListName})

	require.ErrorIs(t, run.err, domaininstance.ErrInvalidConfig)
	assert.NotContains(t, run.out, instanceCommandDefaultName)
}

// TestRunInstanceListRejectsInvalidInstancesValue verifies that an instances key
// which is not a mapping is reported by the command.
func TestRunInstanceListRejectsInvalidInstancesValue(t *testing.T) {
	t.Parallel()

	lockInstanceCommandState(t)
	resetInstanceCommandState(t)

	viper.Set("instances", instanceCommandHTTPScheme)

	run := runInstanceCommand(t, []string{InstanceListName, InstanceAllFlag})

	require.ErrorIs(t, run.err, domaininstance.ErrNoConfigInstances)
	assert.NotContains(t, run.out, instanceCommandDefaultName)
}
