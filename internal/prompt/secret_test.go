// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSecret is the secret the tests supply.
const testSecret = "correct horse battery staple"

// TestSecretReadsRedirectedInput verifies that redirected input is read whole,
// that one line ending is removed, and that nothing is written to the prompt
// stream.
func TestSecretReadsRedirectedInput(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input string
		want  string
	}{
		"newline":         {input: testSecret + "\n", want: testSecret},
		"carriage return": {input: testSecret + "\r\n", want: testSecret},
		"double newline":  {input: testSecret + "\n\n", want: testSecret + "\n"},
		"bare":            {input: testSecret, want: testSecret},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var prompts strings.Builder

			secret, err := newTestTerminal(strings.NewReader(test.input), &prompts, false, "").Secret()

			require.NoError(t, err)
			assert.Equal(t, test.want, secret)
			assert.Empty(t, prompts.String())
		})
	}
}

// TestSecretPromptsOnTerminal verifies that a terminal input is read hidden
// after a prompt, and that the prompt never carries the secret.
func TestSecretPromptsOnTerminal(t *testing.T) {
	t.Parallel()

	var prompts strings.Builder

	secret, err := newTestTerminal(strings.NewReader(""), &prompts, true, testSecret+"\n").Secret()

	require.NoError(t, err)
	assert.Equal(t, testSecret, secret)
	assert.Equal(t, "Password: \n", prompts.String())
}

// TestSecretRejectsEmptyInput verifies that empty input is refused on both
// paths, so an empty credential is never stored.
func TestSecretRejectsEmptyInput(t *testing.T) {
	t.Parallel()

	_, pipedErr := newTestTerminal(strings.NewReader("\n"), io.Discard, false, "").Secret()
	require.ErrorIs(t, pipedErr, ErrEmptySecret)
	assert.Contains(t, pipedErr.Error(), "validate redirected secret")

	_, promptErr := newTestTerminal(strings.NewReader(""), io.Discard, true, "").Secret()
	require.ErrorIs(t, promptErr, ErrEmptySecret)
	assert.Contains(t, promptErr.Error(), "validate prompted secret")
}

// TestSecretReportsStreamFailures verifies that a failing input, a failing
// prompt stream, and a failing hidden read are reported without the secret.
func TestSecretReportsStreamFailures(t *testing.T) {
	t.Parallel()

	_, readErr := newTestTerminal(failingReader{}, io.Discard, false, "").Secret()
	require.ErrorIs(t, readErr, errTestRead)
	assert.Contains(t, readErr.Error(), "read secret from standard input")

	_, writeErr := newTestTerminal(strings.NewReader(""), failingWriter{}, true, testSecret).Secret()
	require.ErrorIs(t, writeErr, errTestWrite)
	assert.Contains(t, writeErr.Error(), "write secret prompt")

	hiddenFailure := errors.New("terminal is unavailable")
	input := fakeInput{Reader: strings.NewReader(""), hiddenErr: hiddenFailure, hidden: "", terminal: true}
	terminal := New(input, io.Discard)

	_, hiddenErr := terminal.Secret()
	require.ErrorIs(t, hiddenErr, hiddenFailure)
	assert.Contains(t, hiddenErr.Error(), "read secret from terminal")
	assert.NotContains(t, hiddenErr.Error(), testSecret)
}
