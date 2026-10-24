// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Question describes one confirmation presented to the operator.
type Question struct {
	// Prompt is the question presented to the operator.
	Prompt string
	// Declined names what does not happen when the operator declines, such as
	// "no credential was stored". It is reported on the prompt stream.
	Declined string
	// Assumed reports that the operator pre-accepted the operation. It is the
	// only way a redirected workflow can proceed, because a prompt needs a
	// terminal.
	Assumed bool
}

// ErrConfirmationUnavailable reports that a confirmation was required but no
// terminal was attached to standard input.
var ErrConfirmationUnavailable = errors.New(
	"confirmation requires a terminal; pass --yes for non-interactive use",
)

// affirmativeAnswers are the confirmations accepted as consent.
var affirmativeAnswers = []string{"y", "yes"}

// Confirm reports whether the operator accepted a question.
//
// A prompt is impossible without a terminal, so a redirected workflow must
// pre-accept the operation rather than silently proceed. A declined question is
// reported on the prompt stream, so the operator sees that nothing happened.
//
// Parameters:
//   - question: the question and the pre-acceptance selection.
//
// Returns:
//   - bool: true when the operation was pre-accepted or the operator agreed.
//   - error: a wrapped [ErrConfirmationUnavailable] when no terminal is
//     attached, or a wrapped prompt or notice failure.
func (t Terminal) Confirm(question Question) (bool, error) {
	if question.Assumed {
		return true, nil
	}

	if !t.isTerminal() {
		return false, fmt.Errorf("confirm %q: %w", question.Prompt, ErrConfirmationUnavailable)
	}

	answer, err := t.ask(question.Prompt)
	if err != nil {
		return false, fmt.Errorf("ask for confirmation: %w", err)
	}

	if slices.Contains(affirmativeAnswers, answer) {
		return true, nil
	}

	_, err = fmt.Fprintf(t.out, "Canceled; %s.\n", question.Declined)
	if err != nil {
		return false, fmt.Errorf("report declined confirmation: %w", err)
	}

	return false, nil
}

// ask writes a prompt and reads one answer line from the terminal.
//
// Parameters:
//   - prompt: question presented to the operator.
//
// Returns:
//   - string: the trimmed, lower-case answer.
//   - error: a wrapped error when the prompt or the answer cannot be written or
//     read.
func (t Terminal) ask(prompt string) (string, error) {
	_, writeErr := fmt.Fprintf(t.out, "%s [y/N]: ", prompt)
	if writeErr != nil {
		return "", fmt.Errorf("write confirmation prompt: %w", writeErr)
	}

	answer, readErr := bufio.NewReader(t.in).ReadString('\n')
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return "", fmt.Errorf("read confirmation answer: %w", readErr)
	}

	return strings.ToLower(strings.TrimSpace(answer)), nil
}
