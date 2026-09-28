// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// coordinator is the password use-case surface the commands depend on.
//
// [github.com/nicholas-fedor/agh-cli/internal/app.Credentials] satisfies the
// interface. The interface is declared here so the commands can be exercised
// without an operating system credential store.
type coordinator interface {
	// ClearAllPasswords removes every credential of the configured service.
	//
	// Parameters:
	//   - ctx: request-scoped cancellation signal.
	//
	// Returns:
	//   - app.PasswordClearResult: the cleared service.
	//   - error: non-nil when the credentials could not be cleared.
	ClearAllPasswords(ctx context.Context) (app.PasswordClearResult, error)
	// ClearPassword removes the stored credential of one instance.
	//
	// Parameters:
	//   - ctx: request-scoped cancellation signal.
	//   - name: configured instance name.
	//
	// Returns:
	//   - app.PasswordClearResult: the cleared identity and whether a credential
	//     was removed.
	//   - error: non-nil when the credential could not be cleared.
	ClearPassword(ctx context.Context, name string) (app.PasswordClearResult, error)
	// SetPassword stores one credential and repoints the instance at it.
	//
	// Parameters:
	//   - ctx: request-scoped cancellation signal.
	//   - name: configured instance name.
	//   - key: credential key, or an empty string for the configured key.
	//   - secret: secret read by the command layer.
	//
	// Returns:
	//   - app.PasswordSetResult: the written identity and whether it replaced a
	//     credential.
	//   - error: non-nil when the credential could not be stored.
	SetPassword(
		ctx context.Context,
		name, key, secret string,
	) (app.PasswordSetResult, error)
	// StatusPassword reports credential store state for the named instances.
	//
	// Parameters:
	//   - ctx: request-scoped cancellation signal.
	//   - names: instance names to inspect, or an empty slice for every instance.
	//
	// Returns:
	//   - app.PasswordReport: the backend, the service, and one entry per
	//     instance.
	//   - error: non-nil when a requested name is unknown.
	StatusPassword(ctx context.Context, names []string) (app.PasswordReport, error)
}

// factory builds the password coordinator for one command execution.
type factory func() (coordinator, error)

// terminalReader reads a secret from a terminal without echoing it.
type terminalReader func(reader io.Reader) ([]byte, error)

// terminalProbe reports whether a reader is connected to a terminal.
type terminalProbe func(reader io.Reader) bool

// streams carries the process input and terminal seams the commands use.
//
// The seams are function values owned by one constructed command tree, so
// repeated construction never shares state between executions.
type streams struct {
	// coordinator builds the password use-case coordinator.
	coordinator factory
	// isTerminal reports whether command input is a terminal.
	isTerminal terminalProbe
	// readPassword reads a secret from command input without echoing it.
	readPassword terminalReader
}

// confirmationRequest describes one prompt presented to the operator.
type confirmationRequest struct {
	// prompt is the question presented to the operator.
	prompt string
	// assumed reports that the operator pre-accepted the operation. It is the
	// only way a redirected workflow can proceed, because a prompt needs a
	// terminal.
	assumed bool
}

// allFlagName is the published name of the service-wide selection flag.
const allFlagName = "all"

// jsonFlagName is the published name of the machine-readable report flag.
const jsonFlagName = "json"

// keyFlagName is the published name of the credential key override flag.
const keyFlagName = "key"

// yesFlagName is the published name of the confirmation skip flag.
const yesFlagName = "yes"

// affirmativeAnswers are the confirmations accepted as consent.
var affirmativeAnswers = []string{"y", "yes"}

// ErrConfirmationUnavailable reports that a confirmation was required but no
// terminal was attached to standard input.
var ErrConfirmationUnavailable = errors.New(
	"confirmation requires a terminal; pass --yes for non-interactive use",
)

// ErrEmptySecret reports that the supplied secret contained no characters.
var ErrEmptySecret = errors.New("no secret was supplied")

// ErrInvalidSelection reports a clear request naming an instance while asking for
// every credential, or naming neither.
var ErrInvalidSelection = errors.New("specify an instance name or --all")

// ErrNotAFile reports that standard input is not a terminal file descriptor, so a
// hidden prompt is impossible.
var ErrNotAFile = errors.New("standard input is not a terminal file")

// newStreams builds the production input seams.
//
// The coordinator closure converts the application coordinator to the narrow
// command surface, which keeps the credential store adapter and the
// configuration package out of this package.
//
// Returns:
//   - *streams: production dependencies for the password commands.
func newStreams() *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return app.NewCredentialsCoordinator()
		},
		isTerminal: terminalIsInput,
		readPassword: func(reader io.Reader) ([]byte, error) {
			descriptor, err := fileDescriptor(reader)
			if err != nil {
				return nil, fmt.Errorf("locate terminal: %w", err)
			}

			return term.ReadPassword(descriptor)
		},
	}
}

// fileDescriptor returns the descriptor of a terminal-backed reader.
//
// Callers check the result of terminalIsInput first, so an unusable reader is
// reported by [ErrNotAFile] rather than silently read.
//
// Parameters:
//   - reader: command input.
//
// Returns:
//   - int: the file descriptor of the reader.
//   - error: ErrNotAFile when the reader is not a terminal file.
func fileDescriptor(reader io.Reader) (int, error) {
	file, ok := reader.(*os.File)
	if !ok {
		return 0, ErrNotAFile
	}

	return int(file.Fd()), nil
}

// terminalIsInput reports whether command input is a terminal.
//
// Parameters:
//   - reader: command input.
//
// Returns:
//   - bool: true when the input is connected to a terminal.
func terminalIsInput(reader io.Reader) bool {
	descriptor, err := fileDescriptor(reader)
	if err != nil {
		return false
	}

	return term.IsTerminal(descriptor)
}

// trimSecretLineEnding removes one trailing newline from a secret.
//
// A secret piped through a shell commonly carries a trailing newline, which is
// part of the transport and not part of the password. Only one terminator is
// removed, so a password that genuinely ends in a newline still round-trips
// through a double redirect.
//
// Parameters:
//   - secret: raw secret bytes rendered as text.
//
// Returns:
//   - string: the secret without one trailing carriage return and newline pair.
func trimSecretLineEnding(secret string) string {
	trimmed := strings.TrimSuffix(secret, "\n")

	return strings.TrimSuffix(trimmed, "\r")
}

// askTerminal writes a prompt and reads one answer line from a terminal.
//
// Parameters:
//   - out: destination for the prompt.
//   - reader: terminal-backed input the answer is read from.
//   - prompt: question presented to the operator.
//
// Returns:
//   - string: the trimmed answer.
//   - error: a wrapped error when the prompt or the answer cannot be written or
//     read.
func askTerminal(out io.Writer, reader io.Reader, prompt string) (string, error) {
	_, writeErr := fmt.Fprintf(out, "%s [y/N]: ", prompt)
	if writeErr != nil {
		return "", fmt.Errorf("write confirmation prompt: %w", writeErr)
	}

	answer, readErr := bufio.NewReader(reader).ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("read confirmation answer: %w", readErr)
	}

	return strings.ToLower(strings.TrimSpace(answer)), nil
}

// confirmed reports whether the operator accepted a prompt.
//
// A prompt is impossible without a terminal, so a redirected workflow must
// pre-accept the operation rather than silently proceed.
//
// Parameters:
//   - out: destination for the prompt.
//   - reader: command input.
//   - isTerminal: probe deciding whether a prompt is possible.
//   - ask: the question and the pre-acceptance selection.
//
// Returns:
//   - bool: true when the operation may proceed.
//   - error: a wrapped [ErrConfirmationUnavailable] when no terminal is
//     attached, or a wrapped read or write error.
func confirmed(
	out io.Writer,
	reader io.Reader,
	isTerminal terminalProbe,
	ask confirmationRequest,
) (bool, error) {
	if ask.assumed {
		return true, nil
	}

	if !isTerminal(reader) {
		return false, fmt.Errorf("confirm %q: %w", ask.prompt, ErrConfirmationUnavailable)
	}

	answer, err := askTerminal(out, reader, ask.prompt)
	if err != nil {
		return false, fmt.Errorf("ask for confirmation: %w", err)
	}

	return isAffirmative(answer), nil
}

// isAffirmative reports whether an answer consents to the operation.
//
// Anything other than an explicit yes is treated as a refusal, so an unexpected
// answer never destroys a stored credential.
//
// Parameters:
//   - answer: trimmed answer read from the terminal.
//
// Returns:
//   - bool: true when the answer consents.
func isAffirmative(answer string) bool {
	return slices.Contains(affirmativeAnswers, answer)
}

// NewCommand creates the password command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The password command.
func NewCommand() *cobra.Command {
	// The exported constructor is the production entry point, so this subpackage
	// tests build the same tree over an injected coordinator.
	return newCommandGroup(newStreams())
}

// newCommandGroup creates the password command over explicit dependencies.
//
// Parameters:
//   - seams: input seams and password coordinator factory.
//
// Returns:
//   - *cobra.Command: The password command bound to the supplied seams.
func newCommandGroup(seams *streams) *cobra.Command {
	passwordCmd := &cobra.Command{
		Use:   "password",
		Short: "Manage the stored password of an instance",
		Long: `Store, inspect, and remove the AdGuard Home administrator password
of a configured instance in the operating system credential store. The
password is a secret, so it is never an argument and no command prints
it. The username is configuration and is managed separately by 'agh-cli
instance credentials username'.`,
	}

	// Register subcommands.
	passwordCmd.AddCommand(
		newSetCommand(seams),
		newClearCommand(seams),
		newStatusCommand(seams),
	)

	return passwordCmd
}
