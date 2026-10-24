// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrEmptySecret reports that the supplied secret contained no characters.
var ErrEmptySecret = errors.New("no secret was supplied")

// Secret returns the secret supplied on the command input.
//
// A terminal input is read without echoing, and a redirected input is read
// whole, so a piped secret never appears on screen. Either way the secret is
// returned only to the caller and is never rendered, logged, or reported.
//
// Returns:
//   - string: the secret supplied by the operator.
//   - error: a wrapped error when the hidden read or the redirected read fails,
//     or [ErrEmptySecret] when nothing was supplied.
func (t Terminal) Secret() (string, error) {
	if t.isTerminal() {
		secret, err := t.promptSecret()
		if err != nil {
			return "", fmt.Errorf("read secret: %w", err)
		}

		return secret, nil
	}

	secret, err := t.pipedSecret()
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}

	return secret, nil
}

// pipedSecret reads a secret that was redirected into the command.
//
// Returns:
//   - string: the secret supplied by the operator.
//   - error: a wrapped error when the input cannot be read, or
//     [ErrEmptySecret] when nothing was supplied.
func (t Terminal) pipedSecret() (string, error) {
	data, err := io.ReadAll(t.in)
	if err != nil {
		return "", fmt.Errorf("read secret from standard input: %w", err)
	}

	secret, err := validateSecret(trimSecretLineEnding(string(data)))
	if err != nil {
		return "", fmt.Errorf("validate redirected secret: %w", err)
	}

	return secret, nil
}

// promptSecret reads a secret from the terminal without echoing it.
//
// The prompt goes to the error stream, so a redirected workflow and a
// machine-readable report are never polluted by it.
//
// Returns:
//   - string: the secret supplied by the operator.
//   - error: a wrapped error when the prompt or the hidden read fails, or
//     [ErrEmptySecret] when nothing was supplied.
func (t Terminal) promptSecret() (string, error) {
	_, writeErr := fmt.Fprint(t.out, "Password: ")
	if writeErr != nil {
		return "", fmt.Errorf("write secret prompt: %w", writeErr)
	}

	data, readErr := t.readHidden()
	if readErr != nil {
		return "", fmt.Errorf("read secret from terminal: %w", readErr)
	}

	_, newlineErr := fmt.Fprintln(t.out)
	if newlineErr != nil {
		return "", fmt.Errorf("close secret prompt: %w", newlineErr)
	}

	secret, err := validateSecret(trimSecretLineEnding(string(data)))
	if err != nil {
		return "", fmt.Errorf("validate prompted secret: %w", err)
	}

	return secret, nil
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

// validateSecret rejects a secret that carries no characters.
//
// Storing an empty credential would replace a working password with one that
// cannot authenticate, so the input is refused before anything is stored.
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
