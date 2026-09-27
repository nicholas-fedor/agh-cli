// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// RewriteDiffTestModified is the domain whose enabled state differs between sets.
	rewriteDiffTestModified = "modified.example"
	// RewriteDiffTestRemoved is the domain present only in the baseline set.
	rewriteDiffTestRemoved = "removed.example"
	// RewriteDiffTestAdded is the domain present only in the comparison set.
	rewriteDiffTestAdded = "added.example"
	// RewriteDiffTestSame is the domain whose values match across both sets.
	rewriteDiffTestSame = "same.example"
)

// TestDiffRulesHandlesPresenceAwareRules verifies add, remove, modify, and stable input order.
func TestDiffRulesHandlesPresenceAwareRules(t *testing.T) {
	t.Parallel()

	baseline := []Rule{
		{Domain: new(rewriteDiffTestModified), Answer: new(rewriteTestAnswer), Enabled: new(true)},
		{Domain: new(rewriteDiffTestRemoved), Answer: new(rewriteTestAnswer), Enabled: new(false)},
		{Domain: new(rewriteDiffTestSame), Answer: new(rewriteTestAnswer), Enabled: new(false)},
	}
	comparison := []Rule{
		{Domain: new(rewriteDiffTestSame), Answer: new(rewriteTestAnswer), Enabled: new(false)},
		{Domain: new(rewriteDiffTestAdded), Answer: new(rewriteTestAnswer), Enabled: new(true)},
		{Domain: new(rewriteDiffTestModified), Answer: new(rewriteTestAnswer), Enabled: new(false)},
	}

	diff := DiffRules(baseline, comparison)

	require.Len(t, diff.Added, 1)
	assert.Equal(t, rewriteDiffTestAdded, diff.Added[0].Domain)
	assert.Equal(t, ChangeAdded, diff.Added[0].Change)
	assert.Nil(t, diff.Added[0].Old)
	require.Len(t, diff.Removed, 1)
	assert.Equal(t, rewriteDiffTestRemoved, diff.Removed[0].Domain)
	assert.Equal(t, ChangeRemoved, diff.Removed[0].Change)
	assert.Nil(t, diff.Removed[0].New)
	require.Len(t, diff.Modified, 1)
	assert.Equal(t, rewriteDiffTestModified, diff.Modified[0].Domain)
	assert.Equal(t, ChangeModified, diff.Modified[0].Change)
	assert.True(t, ruleEnabled(*diff.Modified[0].Old))
	assert.False(t, ruleEnabled(*diff.Modified[0].New))
}

// TestDiffRulesTreatsAbsentEnabledAsUnchanged verifies nil and false states compare equally.
func TestDiffRulesTreatsAbsentEnabledAsUnchanged(t *testing.T) {
	t.Parallel()

	baseline := []Rule{{Domain: new(rewriteDiffTestSame), Answer: new(rewriteTestAnswer)}}
	comparison := []Rule{{
		Domain:  new(rewriteDiffTestSame),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}}

	diff := DiffRules(baseline, comparison)

	assert.Empty(t, diff.Added)
	assert.Empty(t, diff.Removed)
	assert.Empty(t, diff.Modified)
}
