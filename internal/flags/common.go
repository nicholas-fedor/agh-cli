// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"github.com/spf13/pflag"
)

// CommonFlags stores values for flags shared by multiple commands.
type CommonFlags struct {
	// Config is the configuration path selected by --config or -c.
	Config string
}

// Bind registers the configuration flag and binds its value to the receiver.
//
// Parameters:
//   - flags: flag set that receives the configuration flag.
func (cf *CommonFlags) Bind(flags *pflag.FlagSet) {
	// --config, -c: Path to the configuration file
	flags.StringVarP(
		&cf.Config,
		"config",
		"c",
		"",
		"Path to config file",
	)
}
