// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// newInstanceAddCommand creates the instance add command and binds its flags.
//
// The command deliberately publishes no username or password flag. Both are
// authentication details, and an argument value is visible in process listings
// and shell history, so both are owned by the credential workflow. The command
// therefore adds an instance and nothing else, and the operator configures
// authentication with 'agh-cli instance credentials username set' and
// 'agh-cli instance credentials password set'.
//
// Returns:
//   - *cobra.Command: The add command with its own flag values.
func newInstanceAddCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "add <instance> <host>",
		Short: "Add a new instance configuration",
		Long: `Add a new instance configuration without any credentials. Set the
administrator username with 'agh-cli instance credentials username set
<instance> <username>' and the password with 'agh-cli instance credentials
password set <instance>'. The password is read from a hidden prompt, so
it never appears in a process listing or shell history.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstanceAdd(cmd, args, values)
		},
	}

	command.Flags().StringVarP(&values.scheme, "scheme", "s", "https", "HTTP scheme")

	return command
}

// runInstanceAdd adds a new instance configuration to the config file.
//
// The instance is stored without credentials, so the save never writes an
// authentication detail the operator did not choose to set.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: positional arguments, where args[0] is the instance name and args[1] is the host.
//   - values: Bound flag values carrying the optional instance scheme.
//
// Returns:
//   - error: non-nil when config loading, validation, or save fails.
func runInstanceAdd(cmd *cobra.Command, args []string, values *flagValues) error {
	addErr := app.AddInstance(app.InstanceAddRequest{
		ConfigPath: app.ConfigPath(),
		Name:       args[0],
		Host:       args[1],
		Scheme:     values.scheme,
	})
	if addErr != nil {
		return fmt.Errorf("add instance: %w", addErr)
	}

	cmd.Printf("Instance %q added\n", args[0])

	return nil
}
