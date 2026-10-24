// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestFormatRewrite verifies neutral rewrite formatting.
func TestFormatRewrite(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value RewriteValue
		want  string
	}{
		{
			name:  "enabled",
			value: RewriteValue{Answer: "192.0.2.1", Enabled: true},
			want:  "192.0.2.1 (enabled)",
		},
		{
			name:  "disabled",
			value: RewriteValue{Answer: "example.test", Enabled: false},
			want:  "example.test (disabled)",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, FormatRewrite(test.value))
		})
	}
}

// TestFormatRewriteStatus verifies the rewrite status labels.
func TestFormatRewriteStatus(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "enabled", FormatRewriteStatus(true))
	assert.Equal(t, "disabled", FormatRewriteStatus(false))
}

// TestFormatClientType verifies the client type labels.
func TestFormatClientType(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "auto", FormatClientType(true))
	assert.Equal(t, "static", FormatClientType(false))
}
