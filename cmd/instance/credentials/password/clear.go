// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
	"github.com/nicholas-fedor/agh-cli/internal/prompt"
)

// newClearCommand creates the password clear command and binds its flags.
//
// Returns:
//   - *cobra.Command: The clear command with its own flag values.
func newClearCommand() *cobra.Command {
	values := new(flags.PasswordClearFlags)

	command := &cobra.Command{
		Use:   "clear <instance>",
		Short: "Remove a stored instance credential",
		Long: `Remove a stored credential from the operating system credential store.
Use --all to remove every credential of the configured service.
A mounted secret file and an environment variable are owned by another
system and are never removed here. Use --yes for a non-interactive
workflow.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClear(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runClear removes one instance credential or every credential of the service.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: an optional instance name.
//   - values: Bound flag values carrying the service-wide selection and the
//     confirmation selection.
//
// Returns:
//   - error: a wrapped error when the selection is ambiguous, the operator
//     declines, no configuration is loaded, or the store rejects the delete.
func runClear(cmd *cobra.Command, args []string, values *flags.PasswordClearFlags) error {
	err := values.Validate(args)
	if err != nil {
		return fmt.Errorf("clear credential: %w", err)
	}

	if values.All {
		err = clearService(cmd, values)
	} else {
		err = clearInstance(cmd, args[0], values)
	}

	if err != nil {
		return fmt.Errorf("clear credential: %w", err)
	}

	return nil
}

// clearInstance removes the stored credential of one instance.
//
// Parameters:
//   - cmd: Cobra command context.
//   - name: configured instance name.
//   - values: Bound flag values carrying the confirmation selection.
//
// Returns:
//   - error: a wrapped error when the operator declines, no configuration is
//     loaded, or the store rejects the delete.
func clearInstance(
	cmd *cobra.Command,
	name string,
	values *flags.PasswordClearFlags,
) error {
	accepted, err := prompt.New(cmd.InOrStdin(), cmd.ErrOrStderr()).Confirm(prompt.Question{
		Prompt:   "Remove the stored credential of instance " + strconv.Quote(name) + "?",
		Declined: "no credential was removed",
		Assumed:  values.Yes,
	})
	if err != nil {
		return fmt.Errorf("confirm removal: %w", err)
	}

	if !accepted {
		return nil
	}

	result, err := app.ClearPassword(cmd.Context(), name)
	if err != nil {
		return fmt.Errorf("clear credential of %q: %w", name, err)
	}

	err = output.WritePasswordClear(cmd.OutOrStdout(), cmd.ErrOrStderr(), result)
	if err != nil {
		return fmt.Errorf("report cleared credential of %q: %w", name, err)
	}

	return nil
}

// clearService removes every credential of the configured service.
//
// The configuration is deliberately untouched, so a surviving credential
// reference becomes a visible error rather than a silent change of source.
//
// Parameters:
//   - cmd: Cobra command context.
//   - values: Bound flag values carrying the confirmation selection.
//
// Returns:
//   - error: a wrapped error when the operator declines, no configuration is
//     loaded, or the store rejects the delete.
func clearService(cmd *cobra.Command, values *flags.PasswordClearFlags) error {
	accepted, err := prompt.New(cmd.InOrStdin(), cmd.ErrOrStderr()).Confirm(prompt.Question{
		Prompt:   "Remove every credential of the configured service?",
		Declined: "no credential was removed",
		Assumed:  values.Yes,
	})
	if err != nil {
		return fmt.Errorf("confirm removal: %w", err)
	}

	if !accepted {
		return nil
	}

	result, err := app.ClearAllPasswords(cmd.Context())
	if err != nil {
		return fmt.Errorf("clear credential service: %w", err)
	}

	err = output.WritePasswordClearAll(cmd.OutOrStdout(), result)
	if err != nil {
		return fmt.Errorf("report cleared credential service: %w", err)
	}

	return nil
}
