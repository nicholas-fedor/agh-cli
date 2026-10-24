// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nicholas-fedor/agh-cli/internal/client"
)

// TestClientMutationFlagsBindPublishesFlags verifies the published client
// settings flags and the shared selection flags.
func TestClientMutationFlagsBindPublishesFlags(t *testing.T) {
	t.Parallel()

	fs := parsedFlags(t, new(ClientMutationFlags).Bind)

	assertFlag(t, fs, "use-global", "g", "true", "use global settings")
	assertFlag(t, fs, "filtering", "f", "false", "enable filtering")
	assertFlag(t, fs, "parental", "p", "false", "enable parental control")
	assertFlag(t, fs, "safebrowsing", "s", "false", "enable safebrowsing")
	assertFlag(t, fs, "id", "I", "[]", "client IDs (IP, CIDR, MAC, or ClientID)")
	assertFlag(t, fs, "all", "a", "false", "target all instances")
}

// TestClientMutationFlagsSettingsPreservesExplicitValues verifies that explicit
// false values reach the settings rather than the defaults.
func TestClientMutationFlagsSettingsPreservesExplicitValues(t *testing.T) {
	t.Parallel()

	values := new(ClientMutationFlags)
	parsedFlags(t, values.Bind,
		"--id=192.0.2.10", "--use-global=false", "--filtering=false", "--parental=true", "--safebrowsing=false",
	)

	assert.Equal(t, client.Settings{
		Name:                "desk",
		IDs:                 []string{"192.0.2.10"},
		UseGlobalSettings:   false,
		FilteringEnabled:    false,
		ParentalEnabled:     true,
		SafebrowsingEnabled: false,
	}, values.Settings("desk"))
}

// TestClientMutationFlagsSettingsKeepsDefaults verifies the published defaults
// of a command parsed without flags.
func TestClientMutationFlagsSettingsKeepsDefaults(t *testing.T) {
	t.Parallel()

	values := new(ClientMutationFlags)
	parsedFlags(t, values.Bind)

	assert.Equal(t, client.Settings{
		Name:                "desk",
		IDs:                 []string{},
		UseGlobalSettings:   true,
		FilteringEnabled:    false,
		ParentalEnabled:     false,
		SafebrowsingEnabled: false,
	}, values.Settings("desk"))
}
