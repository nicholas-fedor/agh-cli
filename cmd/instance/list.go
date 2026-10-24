// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newInstanceListCommand creates the instance list command and binds its flags.
//
// Returns:
//   - *cobra.Command: The list command with its own flag values.
func newInstanceListCommand() *cobra.Command {
	values := new(flags.InstanceListFlags)

	command := &cobra.Command{
		Use:   "list",
		Short: "List configured instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstanceList(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runInstanceList lists all configured instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//   - values: Bound flag values selecting the instance scope.
//
// Returns:
//   - error: Non-nil when the configured instances cannot be read or resolved.
func runInstanceList(cmd *cobra.Command, _ []string, values *flags.InstanceListFlags) error {
	configs, err := app.ListInstances(cmd.Context(), app.InstanceListRequest{
		All: values.All,
	})
	if err != nil {
		return fmt.Errorf("resolve instances: %w", err)
	}

	err = output.WriteInstanceNames(cmd.OutOrStdout(), configs)
	if err != nil {
		return fmt.Errorf("list instances: %w", err)
	}

	return nil
}
