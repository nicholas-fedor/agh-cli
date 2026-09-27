// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newFilteringAddURLCommand creates the add-url command.
//
// Returns:
//   - *cobra.Command: A fresh add-url command owning its selection flags.
func newFilteringAddURLCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "add-url <name> <url>",
		Short: "Add a filter URL",
		Args:  cobra.ExactArgs(2),
		RunE:  runFilteringAddURL,
	}

	command.Flags().BoolP("whitelist", "w", false, "add to whitelist")
	registerFilteringSelectionFlags(command)

	return command
}

// runFilteringAddURL adds a filter URL to one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Filter name and URL arguments.
//
// Returns:
//   - error: An error when flag parsing or a per-instance request fails.
func runFilteringAddURL(cmd *cobra.Command, args []string) error {
	selection, err := currentFilteringSelection(cmd)
	if err != nil {
		return fmt.Errorf("parse filtering flags: %w", err)
	}

	whitelist, err := filteringURLFromFlags(cmd)
	if err != nil {
		return fmt.Errorf("parse filtering flags: %w", err)
	}

	results, operationErr := app.NewFilteringManagement().AddURL(
		cmd.Context(),
		selection,
		args[0],
		args[1],
		whitelist,
	)
	outputErr := writeFilteringMutationResults(cmd, results)

	err = errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("run filtering add-url: %w", err)
	}

	return nil
}
