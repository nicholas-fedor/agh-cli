// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVersionFlags_Bind verifies version flags bind to a flag set.
func TestVersionFlags_Bind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		vf   *VersionFlags
	}{
		{
			name: "binds with default values",
			vf:   new(VersionFlags),
		},
		{
			name: "binds with pre-existing values",
			vf: &VersionFlags{
				Config:  "/tmp/config.yaml",
				Verbose: false,
				JSON:    true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			tt.vf.Bind(fs)

			json, err := fs.GetBool("json")
			require.NoError(t, err)
			assert.False(t, json)

			verbose, err := fs.GetBool("verbose")
			require.NoError(t, err)
			assert.False(t, verbose)
		})
	}
}

// TestVersionFlags_BindVerboseValues verifies the verbose flag updates the receiver.
func TestVersionFlags_BindVerboseValues(t *testing.T) {
	t.Parallel()

	var vf VersionFlags

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	vf.Bind(fs)

	err := fs.Parse([]string{"--verbose"})
	require.NoError(t, err)

	assert.True(t, vf.Verbose)
}

// TestVersionFlags_BindValues verifies the JSON flag updates the receiver.
func TestVersionFlags_BindValues(t *testing.T) {
	t.Parallel()

	var vf VersionFlags

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	vf.Bind(fs)

	err := fs.Parse([]string{"--json"})
	require.NoError(t, err)

	assert.True(t, vf.JSON)
}
