// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"github.com/spf13/pflag"
)

// RewriteSettingsFlags stores the flags of the rewrite settings update command.
type RewriteSettingsFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// Enabled holds the --enabled flag value.
	Enabled bool
}

// Bind registers the rewrite state and instance-selection flags and binds their
// values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the settings flags.
func (f *RewriteSettingsFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&f.Enabled, "enabled", "e", true, "enable rewrites")
	f.InstanceSelection.Bind(flags)
}
