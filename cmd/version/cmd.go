// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version provides the CLI command for displaying application version information.
package version

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/flags"
)

// NewCommand creates the version command.
//
// Returns:
//   - *cobra.Command: The version command that prints application version information.
func NewCommand() *cobra.Command {
	versionFlags := new(flags.VersionFlags)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the application version",
		Long:  "Print the application version, including commit SHA and build details.",
		Example: `  # Print version
  agh-cli version

  # Print detailed version info
  agh-cli version --verbose

  # Print version as JSON
  agh-cli version --json`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVersionCmd(cmd, versionFlags)
		},
	}

	versionFlags.Bind(versionCmd.Flags())

	return versionCmd
}

// runVersionCmd executes the version command.
//
// Parameters:
//   - cmd: Cobra command used for output.
//   - values: Bound flag values selecting the output format.
//
// Returns:
//   - error: Non-nil if the version output fails.
func runVersionCmd(cmd *cobra.Command, values *flags.VersionFlags) error {
	err := values.Printer()(cmd.OutOrStdout())
	if err != nil {
		return fmt.Errorf("print version: %w", err)
	}

	return nil
}
