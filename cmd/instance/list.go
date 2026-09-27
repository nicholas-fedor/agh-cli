// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newInstanceListCommand creates the instance list command and binds its flags.
//
// Returns:
//   - *cobra.Command: The list command with its own flag values.
func newInstanceListCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "list",
		Short: "List configured instances",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstanceList(cmd, args, values)
		},
	}

	command.Flags().BoolVarP(&values.all, "all", "a", false, "show all instances")

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
func runInstanceList(cmd *cobra.Command, _ []string, values *flagValues) error {
	instances, err := app.InstanceSource()
	if err != nil {
		return fmt.Errorf("resolve instance selection: %w", err)
	}

	configs, err := app.ListInstances(app.InstanceListRequest{
		Instances: instances,
		All:       values.all,
	})
	if err != nil {
		return fmt.Errorf("resolve instances: %w", err)
	}

	for _, cfg := range configs {
		cmd.Println(cfg.Name)
	}

	return nil
}
