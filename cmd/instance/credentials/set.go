// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// setValues stores the flag values bound to one set command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type setValues struct {
	// key holds the --key flag value.
	key string
	// yes holds the --yes flag value.
	yes bool
}

// secretReader reads one secret from the command input.
//
// A terminal input is read without echoing, and a redirected input is read
// whole, so a piped secret never appears on screen. Either way the secret is
// returned only to the caller and is never rendered, logged, or reported.
type secretReader struct {
	// in supplies the secret.
	in io.Reader
	// isTerminal reports whether in requires a hidden prompt.
	isTerminal terminalProbe
	// out receives the hidden prompt.
	out io.Writer
	// readPassword reads a secret from in without echoing it.
	readPassword terminalReader
}

// newSetCommand creates the credentials set command and binds its flags.
//
// The command deliberately publishes no password flag. An argument value is
// visible in process listings, shell history, and command logs, so the only
// supported inputs are a hidden terminal prompt and redirected standard input.
//
// Parameters:
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The set command with its own flag values.
func newSetCommand(seams *streams) *cobra.Command {
	values := &setValues{}

	command := &cobra.Command{
		Use:   "set <name>",
		Short: "Store the credential of a configured instance",
		Long: `Store the credential of a configured instance in the operating system ` +
			`credential store and point the instance at it. The secret is read from a ` +
			`hidden prompt, or from standard input when it is redirected, and it is ` +
			`never echoed or printed. Use --yes for a non-interactive workflow.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSet(cmd, args, values, seams)
		},
	}

	command.Flags().StringVar(
		&values.key,
		keyFlagName,
		"",
		"credential key, defaults to the instance name",
	)
	command.Flags().BoolVarP(
		&values.yes,
		yesFlagName,
		"y",
		false,
		"store the credential without asking for confirmation",
	)

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
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - error: a wrapped error when the secret cannot be read, the operator
//     declines, the coordinator cannot be built, or the store rejects the write.
func runSet(cmd *cobra.Command, args []string, values *setValues, seams *streams) error {
	name := args[0]

	reader := secretReader{
		in:           cmd.InOrStdin(),
		isTerminal:   seams.isTerminal,
		out:          cmd.ErrOrStderr(),
		readPassword: seams.readPassword,
	}

	secret, err := reader.read()
	if err != nil {
		return fmt.Errorf("read secret: %w", err)
	}

	accepted, err := confirmed(
		cmd.ErrOrStderr(),
		cmd.InOrStdin(),
		seams.isTerminal,
		confirmationRequest{
			prompt:  "Store this credential for instance " + strconv.Quote(name) + "?",
			assumed: values.yes,
		},
	)
	if err != nil {
		return fmt.Errorf("confirm credential write: %w", err)
	}

	if !accepted {
		cmd.PrintErrln("Canceled; no credential was stored.")

		return nil
	}

	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	result, err := store.Set(cmd.Context(), name, values.key, secret)
	if err != nil {
		return fmt.Errorf("set credential for %q: %w", name, err)
	}

	reportSetResult(cmd, result)

	return nil
}

// reportSetResult renders the outcome of a stored credential.
//
// Only configuration state is reported. The secret, and any value derived from
// it, never reaches an output stream.
//
// Parameters:
//   - cmd: Cobra command context.
//   - result: outcome of the credential write.
func reportSetResult(cmd *cobra.Command, result app.SetResult) {
	action := "Stored"
	if result.Replaced {
		action = "Replaced"
	}

	cmd.Printf(
		"%s credential for instance %q in %s service %q with key %q.\n",
		action,
		result.Instance,
		result.Backend,
		result.Service,
		result.Key,
	)

	if result.Saved {
		return
	}

	cmd.PrintErrf(
		"Warning: the credential was stored, but the configuration file still "+
			"holds the plaintext password for instance %q. Run the command again.\n",
		result.Instance,
	)
}

// validateSecret rejects a secret that carries no characters.
//
// Storing an empty credential would replace a working password with one that
// cannot authenticate, so the write is refused before the store is touched.
//
// Parameters:
//   - secret: candidate secret.
//
// Returns:
//   - string: the validated secret.
//   - error: [ErrEmptySecret] when the secret is empty.
func validateSecret(secret string) (string, error) {
	if secret == "" {
		return "", ErrEmptySecret
	}

	return secret, nil
}

// piped reads a secret that was redirected into the command.
//
// Parameters:
//
// Returns:
//   - string: the secret supplied by the operator.
//   - error: a wrapped error when the input cannot be read, or
//     [ErrEmptySecret] when nothing was supplied.
func (r secretReader) piped() (string, error) {
	data, err := io.ReadAll(r.in)
	if err != nil {
		return "", fmt.Errorf("read secret from standard input: %w", err)
	}

	secret, err := validateSecret(trimSecretLineEnding(string(data)))
	if err != nil {
		return "", fmt.Errorf("validate redirected secret: %w", err)
	}

	return secret, nil
}

// prompt reads a secret from the terminal without echoing it.
//
// The prompt goes to the error stream, so a redirected workflow and a
// machine-readable report are never polluted by it.
//
// Parameters:
//
// Returns:
//   - string: the secret supplied by the operator.
//   - error: a wrapped error when the prompt or the hidden read fails, or
//     [ErrEmptySecret] when nothing was supplied.
func (r secretReader) prompt() (string, error) {
	_, writeErr := fmt.Fprint(r.out, "Password: ")
	if writeErr != nil {
		return "", fmt.Errorf("write secret prompt: %w", writeErr)
	}

	data, readErr := r.readPassword(r.in)
	if readErr != nil {
		return "", fmt.Errorf("read secret from terminal: %w", readErr)
	}

	_, newlineErr := fmt.Fprintln(r.out)
	if newlineErr != nil {
		return "", fmt.Errorf("close secret prompt: %w", newlineErr)
	}

	secret, err := validateSecret(trimSecretLineEnding(string(data)))
	if err != nil {
		return "", fmt.Errorf("validate prompted secret: %w", err)
	}

	return secret, nil
}

// read returns the secret supplied on the command input.
//
// Parameters:
//
// Returns:
//   - string: the secret supplied by the operator.
//   - error: a wrapped error when the hidden read or the redirected read fails,
//     or [ErrEmptySecret] when nothing was supplied.
func (r secretReader) read() (string, error) {
	if r.isTerminal(r.in) {
		secret, err := r.prompt()
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}

		return secret, nil
	}

	secret, err := r.piped()
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}

	return secret, nil
}
