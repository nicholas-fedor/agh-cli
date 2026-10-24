// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials/password"
	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials/username"
)

// NewCommand creates the credentials command and registers its subcommands.
//
// The tree separates the two halves of instance authentication. A username is
// configuration and a password is a secret, so each has its own set, status, and
// clear. Migration spans both halves, because it moves a whole instance from the
// legacy model, where a username was written at creation alongside a plaintext
// password, to the current one.
//
// Returns:
//   - *cobra.Command: The credentials command.
func NewCommand() *cobra.Command {
	credentialsCmd := &cobra.Command{
		Use:   "credentials",
		Short: "Manage instance authentication",
		Long: `Manage the authentication of configured instances. A username is
configuration and lives in the configuration file; a password is a secret
and lives in the operating system credential store. The two are managed
independently, so either can be changed without disturbing the other.
Use 'migrate' to move an instance written by an older release onto this
model.`,
	}

	// Register subcommands.
	credentialsCmd.AddCommand(
		newMigrateCommand(),
		username.NewCommand(),
		password.NewCommand(),
	)

	return credentialsCmd
}
