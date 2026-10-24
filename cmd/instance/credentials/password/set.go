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

// newSetCommand creates the password set command and binds its flags.
//
// The command deliberately publishes no password flag. An argument value is
// visible in process listings, shell history, and command logs, so the only
// supported inputs are a hidden terminal prompt and redirected standard input.
//
// Returns:
//   - *cobra.Command: The set command with its own flag values.
func newSetCommand() *cobra.Command {
	values := new(flags.PasswordSetFlags)

	command := &cobra.Command{
		Use:   "set <instance>",
		Short: "Store the credential of a configured instance",
		Long: `Store the credential of a configured instance in the operating system
credential store and point the instance at it. The secret is read from a
hidden prompt, or from standard input when it is redirected, and it is
never echoed or printed. Use --yes for a non-interactive workflow.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSet(cmd, args, values)
		},
	}

	values.Bind(command.Flags())

	return command
}

// runSet stores one instance credential.
//
// The secret is read before the confirmation, so a declined confirmation never
// writes a credential and the value is dropped as soon as this function returns.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: positional arguments, where args[0] is the instance name.
//   - values: Bound flag values carrying the credential key and confirmation
//     selection.
//
// Returns:
//   - error: a wrapped error when the secret cannot be read, the operator
//     declines, no configuration is loaded, or the store rejects the write.
func runSet(cmd *cobra.Command, args []string, values *flags.PasswordSetFlags) error {
	name := args[0]
	input := prompt.New(cmd.InOrStdin(), cmd.ErrOrStderr())

	secret, err := input.Secret()
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}

	accepted, err := input.Confirm(prompt.Question{
		Prompt:   "Store this credential for instance " + strconv.Quote(name) + "?",
		Declined: "no credential was stored",
		Assumed:  values.Yes,
	})
	if err != nil {
		return fmt.Errorf("confirm credential write: %w", err)
	}

	if !accepted {
		return nil
	}

	result, err := app.SetPassword(cmd.Context(), name, values.Key, secret)
	if err != nil {
		return fmt.Errorf("set credential for %q: %w", name, err)
	}

	err = output.WritePasswordSet(cmd.OutOrStderr(), cmd.ErrOrStderr(), result)
	if err != nil {
		return fmt.Errorf("report credential for %q: %w", name, err)
	}

	return nil
}
