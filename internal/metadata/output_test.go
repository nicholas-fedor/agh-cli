// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"bytes"
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// failingWriter is a destination that rejects every write.
type failingWriter struct{}

// errWriteFailed is the failure every failingWriter write returns.
var errWriteFailed = errors.New("write failed")

// TestPrintDefault verifies PrintDefault writes a non-empty version string.
func TestPrintDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "writes default version string",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			writer := &bytes.Buffer{}
			err := PrintDefault(writer)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			output := writer.String()
			assert.Contains(t, output, Name)
			assert.Contains(t, output, "\n")
		})
	}
}

// TestPrintVerbose verifies PrintVerbose writes detailed version fields.
func TestPrintVerbose(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "writes verbose output",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			writer := &bytes.Buffer{}
			err := PrintVerbose(writer)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			output := writer.String()
			assert.Contains(t, output, "name:")
			assert.Contains(t, output, "version:")
			assert.Contains(t, output, "goVersion:")
			assert.Contains(t, output, "os:")
			assert.Contains(t, output, "arch:")
		})
	}
}

// TestPrintJSON verifies PrintJSON writes valid version JSON.
func TestPrintJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		wantErr bool
	}{
		{
			name:    "writes JSON output",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			writer := &bytes.Buffer{}
			err := PrintJSON(writer)

			if tt.wantErr {
				require.Error(t, err)

				return
			}

			require.NoError(t, err)

			output := writer.String()
			assert.Contains(t, output, `"name"`)
			assert.Contains(t, output, `"version"`)
		})
	}
}

// TestPrintVerboseIncludesBuildMetadata verifies that an injected commit and
// build time each get their own line, between the version and the toolchain.
//
//nolint:paralleltest // The test sets the package-level build metadata.
func TestPrintVerboseIncludesBuildMetadata(t *testing.T) {
	setBuildMetadata(t, "abc1234", "2026-01-02T03:04:05Z")

	writer := &bytes.Buffer{}
	require.NoError(t, PrintVerbose(writer))

	info := GetInfo()
	assert.Equal(t, "name:      "+Name+"\n"+
		"version:   "+info.Version+"\n"+
		"commitSha: abc1234\n"+
		"buildTime: 2026-01-02 03:04:05 UTC\n"+
		"goVersion: "+info.GoVersion+"\n"+
		"os:        "+info.OS+"\n"+
		"arch:      "+info.Arch+"\n", writer.String())
}

// TestPrintersWrapWriteFailure verifies that every printer returns a write
// failure with its own context.
func TestPrintersWrapWriteFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		printer func(io.Writer) error
		name    string
		context string
	}{
		{name: "default", printer: PrintDefault, context: "write default output"},
		{name: "verbose", printer: PrintVerbose, context: "write verbose output"},
		{name: "json", printer: PrintJSON, context: "encode json"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.printer(failingWriter{})

			require.ErrorIs(t, err, errWriteFailed)
			assert.ErrorContains(t, err, tt.context)
		})
	}
}

// Write fails every write with errWriteFailed.
//
// Returns:
//   - int: always zero.
//   - error: always errWriteFailed.
func (failingWriter) Write([]byte) (int, error) {
	return 0, errWriteFailed
}
