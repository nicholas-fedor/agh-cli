// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// legacyRewriteValue models the entry shape accepted by the compatibility formatter.
type legacyRewriteValue struct {
	// Answer is the value returned for the rewritten domain.
	Answer string
	// Enabled reports whether the rewrite rule is active.
	Enabled bool
}

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

// TestFormatRewriteValueCompatibility verifies legacy entry adaptation.
func TestFormatRewriteValueCompatibility(t *testing.T) {
	t.Parallel()

	entry := &legacyRewriteValue{Answer: "192.0.2.1", Enabled: true}
	assert.Equal(t, "192.0.2.1 (enabled)", FormatRewriteValue(entry))
	assert.Equal(t, "-", FormatRewriteValue((*legacyRewriteValue)(nil)))
}
