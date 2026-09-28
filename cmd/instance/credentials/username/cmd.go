// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// coordinator is the username use-case surface the commands depend on.
//
// [github.com/nicholas-fedor/agh-cli/internal/app.Credentials] satisfies the
// interface. The interface is declared here so the commands can be exercised
// without a configuration file on disk.
type coordinator interface {
	// ClearUsername removes the administrator username of one instance.
	//
	// Parameters:
	//   - name: configured instance name.
	//
	// Returns:
	//   - app.UsernameResult: the instance and the configuration write outcome.
	//   - error: non-nil when the username could not be removed.
	ClearUsername(name string) (app.UsernameResult, error)
	// SetUsername records the administrator username of one instance.
	//
	// Parameters:
	//   - name: configured instance name.
	//   - username: AdGuard Home administrator username.
	//
	// Returns:
	//   - app.UsernameResult: the instance, the recorded username, and the
	//     configuration write outcome.
	//   - error: non-nil when the username could not be recorded.
	SetUsername(name, username string) (app.UsernameResult, error)
	// StatusUsername reports the configured username of the named instances.
	//
	// Parameters:
	//   - names: instance names to inspect, or an empty slice for every instance.
	//
	// Returns:
	//   - app.UsernameReport: one entry per inspected instance.
	//   - error: non-nil when a requested name is unknown.
	StatusUsername(names []string) (app.UsernameReport, error)
}

// factory builds the username coordinator for one command execution.
type factory func() (coordinator, error)

// streams carries the coordinator factory the commands use.
//
// The seam is a function value owned by one constructed command tree, so
// repeated construction never shares state between executions.
type streams struct {
	// coordinator builds the username use-case coordinator.
	coordinator factory
}

// setCommandName is the published name of the set subcommand.
const setCommandName = "set"

// statusCommandName is the published name of the status subcommand.
const statusCommandName = "status"

// clearCommandName is the published name of the clear subcommand.
const clearCommandName = "clear"

// jsonFlagName is the published name of the machine-readable report flag.
const jsonFlagName = "json"

// newStreams builds the production seams.
//
// The coordinator closure converts the application coordinator to the narrow
// command surface, which keeps the configuration package out of this package.
//
// Returns:
//   - *streams: production dependencies for the username commands.
func newStreams() *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return app.NewCredentialsCoordinator()
		},
	}
}

// NewCommand creates the username command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The username command.
func NewCommand() *cobra.Command {
	// The exported constructor is the production entry point, so this subpackage
	// builds the same tree over an injected coordinator in its tests.
	return newCommandGroup(newStreams())
}

// newCommandGroup creates the username command over explicit dependencies.
//
// Parameters:
//   - seams: credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The username command bound to the supplied seams.
func newCommandGroup(seams *streams) *cobra.Command {
	usernameCmd := &cobra.Command{
		Use:   "username",
		Short: "Manage the administrator username of an instance",
		Long: `Manage the AdGuard Home administrator username of a configured
instance. The username is configuration rather than a secret, so it is
stored in the configuration file and is independent of the password:
changing the username leaves a stored password untouched, and storing a
password leaves the username untouched.`,
	}

	// Register subcommands.
	usernameCmd.AddCommand(
		newSetCommand(seams),
		newStatusCommand(seams),
		newClearCommand(seams),
	)

	return usernameCmd
}
