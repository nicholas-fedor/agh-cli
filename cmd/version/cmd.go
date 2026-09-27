// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package version provides the CLI command for displaying application version information.
package version

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/metadata"
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
			return runVersionCmd(cmd)
		},
	}

	versionFlags.Bind(versionCmd.Flags())

	return versionCmd
}

// runVersionCmd executes the version command.
//
// Parameters:
//   - cmd: Cobra command used for output.
//
// Returns:
//   - error: Non-nil if the printer cannot be selected or output fails.
func runVersionCmd(cmd *cobra.Command) error {
	printer, err := selectPrinter(cmd)
	if err != nil {
		return fmt.Errorf("select printer: %w", err)
	}

	err = printer(cmd.OutOrStdout())
	if err != nil {
		return fmt.Errorf("print version: %w", err)
	}

	return nil
}

// selectPrinter returns the appropriate version output printer based on flags.
//
// Parameters:
//   - cmd: Cobra command providing access to the verbose and json flags.
//
// Returns:
//   - func(io.Writer) error: The selected printer function.
//   - error: Non-nil if a flag cannot be retrieved.
func selectPrinter(cmd *cobra.Command) (func(io.Writer) error, error) {
	json, err := cmd.Flags().GetBool("json")
	if err != nil {
		return nil, fmt.Errorf("get json flag: %w", err)
	}

	if json {
		return metadata.PrintJSON, nil
	}

	verbose, err := cmd.Flags().GetBool("verbose")
	if err != nil {
		return nil, fmt.Errorf("get verbose flag: %w", err)
	}

	if verbose {
		return metadata.PrintVerbose, nil
	}

	return metadata.PrintDefault, nil
}
