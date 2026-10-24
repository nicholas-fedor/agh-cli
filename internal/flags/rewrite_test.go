// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/output"
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
)

// TestRewriteRuleFlagsRequestUsesArguments verifies the published rule flag and
// the request built from the arguments.
func TestRewriteRuleFlagsRequestUsesArguments(t *testing.T) {
	t.Parallel()

	values := new(RewriteRuleFlags)
	fs := parsedFlags(t, values.Bind, "--enabled=false")

	assertFlag(t, fs, "enabled", "e", "true", "enable rule")
	assert.Equal(t,
		rewrite.RuleRequest{Domain: "a.example", Answer: "192.0.2.1", Enabled: false},
		values.Request("a.example", "192.0.2.1"),
	)
}

// TestRewriteDeleteFlagsRequireAnswer verifies that a deletion without an answer
// is refused, and that the request carries the flag values.
func TestRewriteDeleteFlagsRequireAnswer(t *testing.T) {
	t.Parallel()

	values := new(RewriteDeleteFlags)
	fs := parsedFlags(t, values.Bind)

	assertFlag(t, fs, "answer", "A", "", "answer/IP to delete")
	assertFlag(t, fs, "enabled", "e", "true", "rule enabled state")
	require.ErrorIs(t, values.Validate(), ErrAnswerRequired)

	require.NoError(t, fs.Parse([]string{"--answer", "192.0.2.1"}))
	require.NoError(t, values.Validate())
	assert.Equal(t,
		rewrite.RuleRequest{Domain: "a.example", Answer: "192.0.2.1", Enabled: true},
		values.Request("a.example"),
	)
}

// TestRewriteListFlagsValidateSortColumn verifies the published sort flag and
// that only the list table's columns are accepted.
func TestRewriteListFlagsValidateSortColumn(t *testing.T) {
	t.Parallel()

	values := new(RewriteListFlags)
	fs := parsedFlags(t, values.Bind)

	assertFlag(t, fs, "sort", "s", "domain", "sort column (domain, answer, status)")
	require.NoError(t, values.Validate())

	values.Sort = output.ChangeSortColumn
	require.ErrorIs(t, values.Validate(), output.ErrUnknownSortColumn)
}

// TestRewriteDiffFlagsValidateSortColumn verifies the published diff flags and
// that only the diff table's columns are accepted.
func TestRewriteDiffFlagsValidateSortColumn(t *testing.T) {
	t.Parallel()

	values := new(RewriteDiffFlags)
	fs := parsedFlags(t, values.Bind, "--file", "rules.yaml", "--sort", "change")

	assertFlag(t, fs, "file", "f", "", "path to YAML/JSON rewrite rules file")
	assertFlag(t, fs, "sort", "s", "domain", "sort column (domain, change)")
	assert.Equal(t, "rules.yaml", values.File)
	require.NoError(t, values.Validate())

	values.Sort = output.AnswerSortColumn
	require.ErrorIs(t, values.Validate(), output.ErrUnknownSortColumn)
}
