// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// clearValues stores the flag values bound to one clear command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type clearValues struct {
	// all holds the --all flag value.
	all bool
	// yes holds the --yes flag value.
	yes bool
}

// newClearCommand creates the credentials clear command and binds its flags.
//
// Parameters:
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The clear command with its own flag values.
func newClearCommand(seams *streams) *cobra.Command {
	values := &clearValues{}

	command := &cobra.Command{
		Use:   "clear <name>",
		Short: "Remove a stored instance credential",
		Long: `Remove a stored credential from the operating system credential store. ` +
			`Use --all to remove every credential of the configured service. ` +
			`A mounted secret file and an environment variable are owned by another ` +
			`system and are never removed here. Use --yes for a non-interactive ` +
			`workflow.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClear(cmd, args, values, seams)
		},
	}

	command.Flags().BoolVar(
		&values.all,
		allFlagName,
		false,
		"remove every credential of the configured service",
	)
	command.Flags().BoolVarP(
		&values.yes,
		yesFlagName,
		"y",
		false,
		"remove the credential without asking for confirmation",
	)

	return command
}

// runClear removes one instance credential or every credential of the service.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: an optional instance name.
//   - values: Bound flag values carrying the service-wide selection and the
//     confirmation selection.
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - error: a wrapped error when the selection is ambiguous, the operator
//     declines, the coordinator cannot be built, or the store rejects the
//     delete.
func runClear(cmd *cobra.Command, args []string, values *clearValues, seams *streams) error {
	err := validateClearSelection(args, values)
	if err != nil {
		return fmt.Errorf("clear credential: %w", err)
	}

	if values.all {
		err = clearService(cmd, seams, values)
	} else {
		err = clearInstance(cmd, args[0], seams, values)
	}

	if err != nil {
		return fmt.Errorf("clear credential: %w", err)
	}

	return nil
}

// validateClearSelection rejects a selection that names an instance and the
// whole service, or neither.
//
// The two selections are mutually exclusive because a service-wide delete
// cannot be scoped back to one instance, so an ambiguous request is refused
// before anything is deleted.
//
// Parameters:
//   - args: positional arguments, optionally naming one instance.
//   - values: Bound flag values carrying the service-wide selection.
//
// Returns:
//   - error: a wrapped [ErrInvalidSelection] for either ambiguous selection.
func validateClearSelection(args []string, values *clearValues) error {
	if values.all && len(args) > 0 {
		return fmt.Errorf("%w: --all and an instance name are mutually exclusive", ErrInvalidSelection)
	}

	if !values.all && len(args) == 0 {
		return ErrInvalidSelection
	}

	return nil
}

// clearInstance removes the stored credential of one instance.
//
// Parameters:
//   - cmd: Cobra command context.
//   - name: configured instance name.
//   - seams: input seams and credential coordinator factory.
//   - values: Bound flag values carrying the confirmation selection.
//
// Returns:
//   - error: a wrapped error when the operator declines, the coordinator cannot
//     be built, or the store rejects the delete.
func clearInstance(
	cmd *cobra.Command,
	name string,
	seams *streams,
	values *clearValues,
) error {
	accepted, err := confirmed(
		cmd.ErrOrStderr(),
		cmd.InOrStdin(),
		seams.isTerminal,
		confirmationRequest{
			prompt:  "Remove the stored credential of instance " + strconv.Quote(name) + "?",
			assumed: values.yes,
		},
	)
	if err != nil {
		return fmt.Errorf("confirm removal: %w", err)
	}

	if !accepted {
		cmd.PrintErrln("Canceled; no credential was removed.")

		return nil
	}

	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	result, err := store.Clear(cmd.Context(), name)
	if err != nil {
		return fmt.Errorf("clear credential of %q: %w", name, err)
	}

	reportClearInstance(cmd, result)

	return nil
}

// clearService removes every credential of the configured service.
//
// The configuration is deliberately untouched, so a surviving credential
// reference becomes a visible error rather than a silent change of source.
//
// Parameters:
//   - cmd: Cobra command context.
//   - seams: input seams and credential coordinator factory.
//   - values: Bound flag values carrying the confirmation selection.
//
// Returns:
//   - error: a wrapped error when the operator declines, the coordinator cannot
//     be built, or the store rejects the delete.
func clearService(cmd *cobra.Command, seams *streams, values *clearValues) error {
	accepted, err := confirmed(
		cmd.ErrOrStderr(),
		cmd.InOrStdin(),
		seams.isTerminal,
		confirmationRequest{
			prompt:  "Remove every credential of the configured service?",
			assumed: values.yes,
		},
	)
	if err != nil {
		return fmt.Errorf("confirm removal: %w", err)
	}

	if !accepted {
		cmd.PrintErrln("Canceled; no credential was removed.")

		return nil
	}

	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	result, err := store.ClearAll(cmd.Context())
	if err != nil {
		return fmt.Errorf("clear credential service: %w", err)
	}

	reportClearService(cmd, result)

	return nil
}

// reportClearInstance renders the outcome of one cleared credential.
//
// Parameters:
//   - cmd: Cobra command context.
//   - result: outcome of the credential delete.
func reportClearInstance(cmd *cobra.Command, result app.ClearResult) {
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

	warnUnsavedReference(cmd, result)
}

// reportClearService renders the outcome of a service-wide clear.
//
// Parameters:
//   - cmd: Cobra command context.
//   - result: outcome of the service-wide delete.
func reportClearService(cmd *cobra.Command, result app.ClearResult) {
	cmd.Printf("Removed every credential in service %q.\n", result.Service)
}

// warnUnsavedReference reports that a deleted credential is still referenced by
// the configuration file.
//
// The reference removal and the configuration write are reported separately by
// the use case, so the notice tells the operator exactly what to repeat.
//
// Parameters:
//   - cmd: Cobra command context.
//   - result: outcome of the credential delete.
func warnUnsavedReference(cmd *cobra.Command, result app.ClearResult) {
	if result.Saved {
		return
	}

	cmd.PrintErrf(
		"Warning: the credential was removed, but instance %q still references it "+
			"in the configuration file. Run the command again.\n",
		result.Instance,
	)
}
