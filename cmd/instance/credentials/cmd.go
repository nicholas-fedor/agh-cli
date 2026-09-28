// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials/password"
	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials/username"
	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// coordinator is the instance-wide credential use-case surface the commands
// depend on.
//
// The password and username use cases live in the sibling subpackages that own
// them, so this surface carries only the operations that span both halves of an
// instance's authentication.
//
// [github.com/nicholas-fedor/agh-cli/internal/app.Credentials] satisfies the
// interface. The interface is declared here so the commands can be exercised
// without an operating system credential store.
type coordinator interface {
	// Migrate moves legacy plaintext passwords into the credential store.
	//
	// Parameters:
	//   - ctx: request-scoped cancellation signal.
	//   - request: migration inputs, including the dry-run selection.
	//
	// Returns:
	//   - app.MigrationReport: one outcome per legacy instance.
	//   - error: non-nil when at least one instance was not migrated.
	Migrate(ctx context.Context, request app.MigrationRequest) (app.MigrationReport, error)
}

// factory builds the credential coordinator for one command execution.
type factory func() (coordinator, error)

// streams carries the coordinator factory the commands use.
//
// The seam is a function value owned by one constructed command tree, so
// repeated construction never shares state between executions.
type streams struct {
	// coordinator builds the credential use-case coordinator.
	coordinator factory
}

// dryRunFlagName is the published name of the migration preview flag.
const dryRunFlagName = "dry-run"

// newStreams builds the production seams.
//
// Returns:
//   - *streams: production dependencies for the credentials commands.
func newStreams() *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return app.NewCredentialsCoordinator()
		},
	}
}

// NewCommand creates the credentials command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The credentials command.
func NewCommand() *cobra.Command {
	// The exported constructor is the production entry point, so the credentials
	// package tests build the same tree over an injected coordinator.
	return newCommandGroup(newStreams())
}

// newCommandGroup creates the credentials command over explicit dependencies.
//
// The tree separates the two halves of instance authentication. A username is
// configuration and a password is a secret, so each has its own set, status, and
// clear. Migration spans both halves, because it moves a whole instance from the
// legacy model, where a username was written at creation alongside a plaintext
// password, to the current one.
//
// Parameters:
//   - seams: credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The credentials command bound to the supplied seams.
func newCommandGroup(seams *streams) *cobra.Command {
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
		newMigrateCommand(seams),
		username.NewCommand(),
		password.NewCommand(),
	)

	return credentialsCmd
}
