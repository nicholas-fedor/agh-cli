// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// passwordFlagDeprecation is the help text of the deprecated --password flag.
//
// The flag stays published because removing it would break existing scripts, but
// the help text names the replacement so a reader never adopts it for new work.
// An argument value is visible in process listings and shell history, which is
// why the replacement reads the secret from a hidden prompt instead.
const passwordFlagDeprecation = "admin password (deprecated: run 'agh-cli instance " +
	"add <name> <host>' without a password, then 'agh-cli instance credentials " +
	"set <name>')"

// newInstanceAddCommand creates the instance add command and binds its flags.
//
// Returns:
//   - *cobra.Command: The add command with its own flag values.
func newInstanceAddCommand() *cobra.Command {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   "add <name> <host>",
		Short: "Add a new instance configuration",
		Long: `Add a new instance configuration. Prefer adding the instance without a ` +
			`password and storing the credential with 'agh-cli instance credentials set'.`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstanceAdd(cmd, args, values)
		},
	}

	command.Flags().StringVarP(&values.scheme, "scheme", "s", "https", "HTTP scheme")
	command.Flags().StringVarP(&values.username, "username", "u", "", "admin username")
	command.Flags().StringVarP(&values.password, "password", "p", "", passwordFlagDeprecation)

	return command
}

// runInstanceAdd adds a new instance configuration to the config file.
//
// The legacy --password flag is preserved, so an existing script keeps working.
// Its help text and the deprecation notice name the supported alternative.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: positional arguments, where args[0] is the instance name and args[1] is the host.
//   - values: Bound flag values carrying the optional instance credentials.
//
// Returns:
//   - error: non-nil when config loading, validation, or save fails.
func runInstanceAdd(cmd *cobra.Command, args []string, values *flagValues) error {
	addErr := app.AddInstance(app.InstanceAddRequest{
		ConfigPath: app.ConfigPath(),
		Name:       args[0],
		Host:       args[1],
		Scheme:     values.scheme,
		Username:   values.username,
		Password:   values.password,
	})
	if addErr != nil {
		return fmt.Errorf("add instance: %w", addErr)
	}

	warnDeprecatedPassword(cmd, args[0], values)

	cmd.Printf("Instance %q added\n", args[0])

	return nil
}

// warnDeprecatedPassword reports the preferred credential workflow when the
// deprecated password flag was used.
//
// The notice goes to the error stream, so a script that parses standard output
// never sees it and the notice is never mistaken for command output.
//
// Parameters:
//   - cmd: Cobra command context.
//   - name: configured instance name that received the password.
//   - values: Bound flag values carrying the optional instance credentials.
func warnDeprecatedPassword(cmd *cobra.Command, name string, values *flagValues) {
	if values.password == "" {
		return
	}

	cmd.PrintErrf(
		"Warning: --password is deprecated because an argument value is visible in "+
			"process listings and shell history. "+
			"Run 'agh-cli instance credentials set %s' instead.\n",
		name,
	)
}
