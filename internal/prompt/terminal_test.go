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

// failingReader always fails a read.
type failingReader struct{}

// failingWriter always fails a write.
type failingWriter struct{}

// noticeFailingWriter accepts a prompt and fails the cancellation notice.
type noticeFailingWriter struct{}

// fakeInput is command input that answers the terminal questions itself.
type fakeInput struct {
	// Reader supplies the redirected input and the confirmation answers.
	io.Reader

	// hiddenErr is returned by the hidden read when set.
	hiddenErr error
	// hidden is the line the hidden read returns.
	hidden string
	// terminal reports whether the input is a terminal.
	terminal bool
}

// errTestRead identifies an intentional input failure.
var errTestRead = errors.New("input is unreadable")

// errTestWrite identifies an intentional output failure.
var errTestWrite = errors.New("output is unwritable")

// TestNewAsksTheOperatingSystemForPlainInput verifies that input that is not a
// file is never treated as a terminal, so a confirmation is refused.
func TestNewAsksTheOperatingSystemForPlainInput(t *testing.T) {
	t.Parallel()

	accepted, err := New(strings.NewReader("y\n"), io.Discard).Confirm(Question{Prompt: "Remove?"})

	require.ErrorIs(t, err, ErrConfirmationUnavailable)
	assert.False(t, accepted)
}

// TestReadHiddenFileRejectsNonFileReader verifies that a hidden read of input
// that is not a file is refused instead of read.
func TestReadHiddenFileRejectsNonFileReader(t *testing.T) {
	t.Parallel()

	line, err := readHiddenFile(strings.NewReader("secret"))

	require.ErrorIs(t, err, ErrNotAFile)
	assert.Nil(t, line)
}

// newTestTerminal returns a Terminal over a fake terminal input.
//
// Parameters:
//   - in: redirected input and confirmation answers.
//   - out: destination for the prompts.
//   - terminal: reports whether the input is treated as a terminal.
//   - hidden: the line the hidden read returns.
//
// Returns:
//   - Terminal: input bound to the fake.
func newTestTerminal(in io.Reader, out io.Writer, terminal bool, hidden string) Terminal {
	return New(fakeInput{Reader: in, hiddenErr: nil, hidden: hidden, terminal: terminal}, out)
}

// IsTerminal reports the configured terminal state.
//
// Returns:
//   - bool: the configured terminal state.
func (f fakeInput) IsTerminal() bool {
	return f.terminal
}

// ReadHidden returns the configured hidden line or failure.
//
// Returns:
//   - []byte: the configured hidden line.
//   - error: the configured failure.
func (f fakeInput) ReadHidden() ([]byte, error) {
	if f.hiddenErr != nil {
		return nil, f.hiddenErr
	}

	return []byte(f.hidden), nil
}

// Read always reports a failure.
//
// Returns:
//   - int: always zero.
//   - error: always [errTestRead].
func (failingReader) Read([]byte) (int, error) {
	return 0, errTestRead
}

// Write always reports a failure.
//
// Returns:
//   - int: always zero.
//   - error: always [errTestWrite].
func (failingWriter) Write([]byte) (int, error) {
	return 0, errTestWrite
}

// Write fails a cancellation notice and accepts everything else.
//
// Parameters:
//   - data: bytes the caller attempted to write.
//
// Returns:
//   - int: the number of bytes accepted.
//   - error: [errTestWrite] for a cancellation notice.
func (noticeFailingWriter) Write(data []byte) (int, error) {
	if strings.HasPrefix(string(data), "Canceled") {
		return 0, errTestWrite
	}

	return len(data), nil
}
