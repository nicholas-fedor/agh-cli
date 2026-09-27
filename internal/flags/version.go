// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"github.com/spf13/pflag"
)

// VersionFlags stores values for the version command.
type VersionFlags struct {
	// CommonFlags stores values for flags shared with other commands.
	CommonFlags

	// Verbose selects detailed, multi-line version output.
	Verbose bool
	// JSON selects indented JSON version output.
	JSON bool
}

// Bind registers the version command's verbose and JSON flags.
//
// Parameters:
//   - flags: flag set that receives the version-specific flags.
func (vf *VersionFlags) Bind(flags *pflag.FlagSet) {
	// --verbose, -v: Output detailed version information
	flags.BoolVarP(
		&vf.Verbose,
		"verbose",
		"v",
		false,
		"Output detailed version information",
	)

	// --json: Output version information in JSON format
	flags.BoolVarP(
		&vf.JSON,
		"json",
		"j",
		false,
		"Output version information in JSON format",
	)
}
