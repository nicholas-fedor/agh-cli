// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
)

// RewriteMutationResult contains the success message for one instance.
type RewriteMutationResult struct {
	// Instance identifies the successful target.
	Instance string
	// Message is the operation-specific success text.
	Message string
}

// RewriteListResult contains the successfully retrieved rules for one instance.
type RewriteListResult struct {
	// Instance identifies the source instance.
	Instance string
	// Rules contains the retrieved rules in service order.
	Rules []RewriteRule
	// Index is the zero-based target position.
	Index int
	// InstanceCount is the number of selected targets.
	InstanceCount int
}

// RewriteSettingsResult contains the successfully retrieved settings for one instance.
type RewriteSettingsResult struct {
	// Instance identifies the source instance.
	Instance string
	// Enabled reports whether DNS rewrites are active.
	Enabled bool
	// Index is the zero-based target position.
	Index int
	// InstanceCount is the number of selected targets.
	InstanceCount int
}

// shapeRewriteRules converts domain rules into display values.
//
// Parameters:
//   - rules: domain rules; nil stays nil.
//
// Returns:
//   - []RewriteRule: display rules, or nil for absent input.
func shapeRewriteRules(rules []rewrite.Rule) []RewriteRule {
	if rules == nil {
		return nil
	}

	shaped := make([]RewriteRule, 0, len(rules))
	for index := range rules {
		shaped = append(shaped, shapeRewriteRule(rules[index]))
	}

	return shaped
}

// shapeRewriteRule converts one domain rule into display values.
//
// Parameters:
//   - rule: domain rule whose optional values are flattened.
//
// Returns:
//   - RewriteRule: display values using empty strings for absent pointers.
func shapeRewriteRule(rule rewrite.Rule) RewriteRule {
	shaped := RewriteRule{}
	if rule.Domain != nil {
		shaped.Domain = *rule.Domain
	}
	if rule.Answer != nil {
		shaped.Answer = *rule.Answer
	}
	if rule.Enabled != nil {
		shaped.Enabled = *rule.Enabled
	}

	return shaped
}
