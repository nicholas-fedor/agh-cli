// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestParseRulesFileSupportsYAMLAndJSON verifies supported file formats and false values.
func TestParseRulesFileSupportsYAMLAndJSON(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"yaml": "- domain: example.com\n  answer: 192.0.2.1\n  enabled: false\n",
		"json": `[{"domain":"example.com","answer":"192.0.2.1","enabled":false}]`,
	}

	for extension, contents := range tests {
		t.Run(extension, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(t.TempDir(), "rules."+extension)
			require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))

			rules, err := ParseRulesFile(path)

			require.NoError(t, err)
			require.Len(t, rules, 1)
			assert.Equal(t, rewriteTestDomain, *rules[0].Domain)
			assert.Equal(t, rewriteTestAnswer, *rules[0].Answer)
			assert.False(t, *rules[0].Enabled)
		})
	}
}

// TestParseRulesFileReportsReadAndParseErrors verifies file failures retain context.
func TestParseRulesFileReportsReadAndParseErrors(t *testing.T) {
	t.Parallel()

	t.Run("read", func(t *testing.T) {
		t.Parallel()

		_, err := ParseRulesFile(filepath.Join(t.TempDir(), "missing.yaml"))

		require.ErrorContains(t, err, "read file")
	})

	t.Run("parse", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join(t.TempDir(), "rules.yaml")
		require.NoError(t, os.WriteFile(path, []byte("[invalid"), 0o600))

		_, err := ParseRulesFile(path)

		require.ErrorContains(t, err, "parse file")
	})
}
