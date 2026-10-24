// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestConfirmAcceptsPreAcceptedQuestion verifies that a pre-accepted question is
// accepted without a terminal and without a prompt.
func TestConfirmAcceptsPreAcceptedQuestion(t *testing.T) {
	t.Parallel()

	var prompts strings.Builder

	accepted, err := newTestTerminal(strings.NewReader(""), &prompts, false, "").
		Confirm(Question{Prompt: "Remove?", Assumed: true})

	require.NoError(t, err)
	assert.True(t, accepted)
	assert.Empty(t, prompts.String())
}

// TestConfirmRequiresTerminal verifies that a question cannot be answered
// without a terminal.
func TestConfirmRequiresTerminal(t *testing.T) {
	t.Parallel()

	accepted, err := newTestTerminal(strings.NewReader("y\n"), io.Discard, false, "").
		Confirm(Question{Prompt: "Remove?", Assumed: false})

	require.ErrorIs(t, err, ErrConfirmationUnavailable)
	assert.False(t, accepted)
	assert.Contains(t, err.Error(), `confirm "Remove?"`)
}

// TestConfirmAcceptsOnlyExplicitYes verifies the accepted answers, that any
// other answer, an empty one included, is a refusal, and that a refusal is
// reported after the prompt.
func TestConfirmAcceptsOnlyExplicitYes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		answer string
		want   bool
	}{
		{answer: "y\n", want: true},
		{answer: " YES \n", want: true},
		{answer: "yes", want: true},
		{answer: "n\n", want: false},
		{answer: "\n", want: false},
		{answer: "", want: false},
		{answer: "yep\n", want: false},
	}

	for _, test := range tests {
		answer, want := test.answer, test.want
		var prompts strings.Builder

		accepted, err := newTestTerminal(strings.NewReader(answer), &prompts, true, "").
			Confirm(Question{Prompt: "Remove?", Declined: "nothing was removed", Assumed: false})

		require.NoError(t, err, "answer %q", answer)
		assert.Equal(t, want, accepted, "answer %q", answer)

		wantPrompts := "Remove? [y/N]: "
		if !want {
			wantPrompts += "Canceled; nothing was removed.\n"
		}

		assert.Equal(t, wantPrompts, prompts.String(), "answer %q", answer)
	}
}

// TestConfirmReportsStreamFailures verifies that a failing prompt stream and a
// failing answer read are reported.
func TestConfirmReportsStreamFailures(t *testing.T) {
	t.Parallel()

	question := Question{Prompt: "Remove?", Assumed: false}

	_, writeErr := newTestTerminal(strings.NewReader("y\n"), failingWriter{}, true, "").Confirm(question)
	require.ErrorIs(t, writeErr, errTestWrite)
	assert.Contains(t, writeErr.Error(), "write confirmation prompt")

	_, readErr := newTestTerminal(failingReader{}, io.Discard, true, "").Confirm(question)
	require.ErrorIs(t, readErr, errTestRead)
	assert.Contains(t, readErr.Error(), "read confirmation answer")

	_, noticeErr := newTestTerminal(strings.NewReader("n\n"), noticeFailingWriter{}, true, "").Confirm(question)
	require.ErrorIs(t, noticeErr, errTestWrite)
	assert.Contains(t, noticeErr.Error(), "report declined confirmation")
}
