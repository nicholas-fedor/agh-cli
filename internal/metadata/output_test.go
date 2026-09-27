// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
