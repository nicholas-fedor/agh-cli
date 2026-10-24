// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/metadata"
)

// failingWriter is a destination that rejects every write.
type failingWriter struct{}

// errWriteFailed is the failure every failingWriter write returns.
var errWriteFailed = errors.New("write failed")

// TestVersionCmd verifies the version command is constructed correctly.
func TestVersionCmd(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "creates command successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := NewCommand()
			assert.NotNil(t, got)
			assert.Equal(t, "version", got.Use)
		})
	}
}

// TestNewCommandSelectsPrinter verifies that each flag combination writes the
// output of the printer it selects to standard output, with JSON taking
// precedence over verbose.
func TestNewCommandSelectsPrinter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		want func(io.Writer) error
		args []string
	}{
		{name: "default", args: nil, want: metadata.PrintDefault},
		{name: "verbose", args: []string{"--verbose"}, want: metadata.PrintVerbose},
		{name: "json", args: []string{"--json"}, want: metadata.PrintJSON},
		{name: "json over verbose", args: []string{"--verbose", "--json"}, want: metadata.PrintJSON},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			expected := &bytes.Buffer{}
			require.NoError(t, tt.want(expected))

			output := &bytes.Buffer{}
			errorsOut := &bytes.Buffer{}
			command := NewCommand()
			command.SetOut(output)
			command.SetErr(errorsOut)
			command.SetArgs(tt.args)

			require.NoError(t, command.ExecuteContext(t.Context()))
			assert.Equal(t, expected.String(), output.String())
			assert.Empty(t, errorsOut.String())
		})
	}
}

// TestNewCommandWrapsWriteFailure verifies that a failed write reaches the
// operator with the command's context.
func TestNewCommandWrapsWriteFailure(t *testing.T) {
	t.Parallel()

	command := NewCommand()
	command.SetOut(failingWriter{})
	command.SetErr(io.Discard)
	command.SetArgs(nil)

	err := command.ExecuteContext(t.Context())

	require.ErrorIs(t, err, errWriteFailed)
	assert.ErrorContains(t, err, "print version")
}

// Write fails every write with errWriteFailed.
//
// Returns:
//   - int: always zero.
//   - error: always errWriteFailed.
func (failingWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}
