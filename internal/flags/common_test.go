// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCommonFlags_Bind verifies common flags bind to a flag set.
func TestCommonFlags_Bind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cf   *CommonFlags
	}{
		{
			name: "binds flags successfully",
			cf:   &CommonFlags{Config: ""},
		},
		{
			name: "binds with pre-existing values",
			cf: &CommonFlags{
				Config: "/path/to/config",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
			tt.cf.Bind(fs)

			config, err := fs.GetString("config")
			require.NoError(t, err)
			assert.Empty(t, config)
		})
	}
}

// TestCommonFlags_BindValues verifies parsed common flag values reach the receiver.
func TestCommonFlags_BindValues(t *testing.T) {
	t.Parallel()

	cf := &CommonFlags{Config: ""}
	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	cf.Bind(fs)

	err := fs.Parse([]string{"--config", "/tmp/config.yaml"})
	require.NoError(t, err)

	assert.Equal(t, "/tmp/config.yaml", cf.Config)
}
