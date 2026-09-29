// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// removal removes one instance and the password it kept in the credential store.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: the instance identity and configuration file path.
//
// Returns:
//   - app.InstanceRemoveResult: the removed instance and the credential outcome.
//   - error: non-nil when the instance or its stored password could not be
//     removed.
type removal func(context.Context, app.InstanceRemoveRequest) (app.InstanceRemoveResult, error)

// removeInstance builds the production instance removal.
//
// The credential store is constructed per execution, because the command layer
// never names the credential store package and a store is never shared between
// two runs.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: the instance identity and configuration file path.
//
// Returns:
//   - app.InstanceRemoveResult: the removed instance and the credential outcome.
//   - error: non-nil when the instance or its stored password could not be
//     removed.
func removeInstance(
	ctx context.Context,
	request app.InstanceRemoveRequest,
) (app.InstanceRemoveResult, error) {
	result, err := app.RemoveInstance(ctx, app.NewCredentialStore(), request)
	if err != nil {
		return result, fmt.Errorf("remove %q: %w", request.Name, err)
	}

	return result, nil
}

// newInstanceRemoveCommand creates the instance remove command.
//
// Parameters:
//   - remove: instance removal used by the command.
//
// Returns:
//   - *cobra.Command: The remove command.
func newInstanceRemoveCommand(remove removal) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <instance>",
		Short: "Remove an instance configuration and its stored password",
		Long: `Remove an instance configuration and the password it kept in the
operating system credential store. A mounted secret file, an environment
variable, and a password kept in the configuration file belong to the
operator or to another system, so nothing is deleted for them.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInstanceRemove(cmd, args, remove)
		},
	}
}

// runInstanceRemove removes an instance configuration and its stored password.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Positional arguments where args[0] is the instance name.
//   - remove: instance removal used by the command.
//
// Returns:
//   - error: non-nil when config loading, removal, or saving fails.
func runInstanceRemove(cmd *cobra.Command, args []string, remove removal) error {
	result, removeErr := remove(cmd.Context(), app.InstanceRemoveRequest{
		ConfigPath: app.ConfigPath(),
		Name:       args[0],
	})
	if removeErr != nil {
		reportFailedInstanceRemoval(cmd, result)

		return fmt.Errorf("remove instance: %w", removeErr)
	}

	reportInstanceRemoval(cmd, result)

	return nil
}

// reportFailedInstanceRemoval renders the credential outcome of a removal that
// did not finish.
//
// The credential store entry is deleted before the configuration is written, so a
// write failure leaves the instance configured with its password already gone.
// That state is reported rather than left to be inferred from the error, because
// the operator otherwise cannot tell whether the secret is still stored. A
// removal that deleted nothing reports nothing: the failure says it all, and the
// instance is untouched.
//
// Parameters:
//   - cmd: Cobra command context.
//   - result: credential outcome reported alongside the failure.
func reportFailedInstanceRemoval(cmd *cobra.Command, result app.InstanceRemoveResult) {
	if !result.Removed {
		return
	}

	cmd.Printf(
		"Removed credential for instance %q with key %q from service %q. "+
			"Instance %q remains configured; run the command again to remove it.\n",
		result.Instance,
		result.Key,
		result.Service,
		result.Instance,
	)
}

// reportInstanceRemoval renders the outcome of one removed instance.
//
// The stored credential is reported only when there was one, so an instance that
// kept its password in the configuration file produces a single line.
//
// Parameters:
//   - cmd: Cobra command context.
//   - result: outcome of the instance removal.
func reportInstanceRemoval(cmd *cobra.Command, result app.InstanceRemoveResult) {
	cmd.Printf("Instance %q removed\n", result.Instance)

	if result.Key == "" {
		return
	}

	if result.Shared {
		cmd.Printf(
			"Kept credential with key %q in service %q: another configured "+
				"instance still reads its password through it.\n",
			result.Key,
			result.Service,
		)

		return
	}

	if !result.Removed {
		cmd.Printf(
			"No stored credential for instance %q with key %q in service %q.\n",
			result.Instance,
			result.Key,
			result.Service,
		)

		return
	}

	cmd.Printf(
		"Removed credential for instance %q with key %q from service %q.\n",
		result.Instance,
		result.Key,
		result.Service,
	)
}
