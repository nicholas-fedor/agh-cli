// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package wildcard

import (
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// flagValues stores the flag values bound to one wildcard command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type flagValues struct {
	// names holds the --instance flag values.
	names []string
	// all holds the --all flag value.
	all bool
}

// wildcardZoneRunner executes one wildcard zone command body.
type wildcardZoneRunner func(*cobra.Command, []string, *flagValues) error

// NewCommand creates the rewrite wildcard command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The wildcard command.
func NewCommand() *cobra.Command {
	wildcardCmd := &cobra.Command{
		Use:   "wildcard",
		Short: "Wildcard rewrite rule operations",
		Long: `Add or remove wildcard rewrite entries across one or more
AdGuard Home instances.`,
	}

	// Register subcommands.
	wildcardCmd.AddCommand(newWildcardAddCommand(), newWildcardRemoveCommand())

	return wildcardCmd
}

// newWildcardZoneCommand creates a wildcard zone command and returns it with
// the fresh flag values its own file binds the command flags to.
//
// Parameters:
//   - use: Command usage line.
//   - short: Command short description.
//   - run: Command body receiving the command, arguments, and bound values.
//
// Returns:
//   - *cobra.Command: The created command awaiting flag registration.
//   - *flagValues: The fresh values the command flags bind to.
func newWildcardZoneCommand(
	use string,
	short string,
	run wildcardZoneRunner,
) (*cobra.Command, *flagValues) {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, values)
		},
	}

	return command, values
}

// selection captures active Cobra and Viper selection state.
//
// Returns:
//   - app.RewriteSelection: The instance selection taken from flags and configuration.
//   - error: An error when the configured instances cannot be read.
func (values *flagValues) selection() (app.RewriteSelection, error) {
	instances, err := app.InstanceSource()
	if err != nil {
		return app.RewriteSelection{}, fmt.Errorf(
			"resolve wildcard instance selection: %w",
			err,
		)
	}

	return app.RewriteSelection{
		Instances:  instances,
		Names:      slices.Clone(values.names),
		ConfigPath: viper.ConfigFileUsed(),
		All:        values.all,
	}, nil
}

// writeWildcardMutationResults renders every successful mutation result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered messages.
//   - results: Per-instance mutation results to render.
//
// Returns:
//   - error: Joined errors from every failed message write.
func writeWildcardMutationResults(
	cmd *cobra.Command,
	results []app.RewriteMutationResult,
) error {
	writer := cmd.OutOrStdout()
	errs := make([]error, 0, len(results))

	for _, result := range results {
		_, err := fmt.Fprintf(writer, "[%s] %s\n", result.Instance, result.Message)
		if err != nil {
			errs = append(errs, fmt.Errorf("write instance %q result: %w", result.Instance, err))
		}
	}

	return errors.Join(errs...)
}
