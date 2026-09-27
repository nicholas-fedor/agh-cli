// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package version

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

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
