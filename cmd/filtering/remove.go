// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newFilteringRemoveURLCommand creates the remove-url command.
//
// Returns:
//   - *cobra.Command: A fresh remove-url command owning its selection flags.
func newFilteringRemoveURLCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "remove-url <url>",
		Short: "Remove a filter URL",
		Args:  cobra.ExactArgs(1),
		RunE:  runFilteringRemoveURL,
	}

	registerFilteringSelectionFlags(command)

	return command
}

// runFilteringRemoveURL removes a filter URL from one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Filter URL argument.
//
// Returns:
//   - error: An error when flag parsing or a per-instance request fails.
func runFilteringRemoveURL(cmd *cobra.Command, args []string) error {
	selection, err := currentFilteringSelection(cmd)
	if err != nil {
		return fmt.Errorf("parse filtering flags: %w", err)
	}

	results, operationErr := app.NewFilteringManagement().RemoveURL(
		cmd.Context(),
		selection,
		args[0],
	)
	outputErr := writeFilteringMutationResults(cmd, results)

	err = errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("remove filtering URL: %w", err)
	}

	return nil
}
