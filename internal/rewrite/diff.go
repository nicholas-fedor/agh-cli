// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

// Change identifies one kind of rewrite-rule difference.
type Change string

// Diff contains differences between two DNS rewrite rule sets.
type Diff struct {
	// Added contains rules present only in the comparison set.
	Added []DiffEntry
	// Removed contains rules present only in the baseline set.
	Removed []DiffEntry
	// Modified contains rules whose enabled state changed.
	Modified []DiffEntry
}

// DiffEntry represents one rewrite-rule difference.
type DiffEntry struct {
	// Domain identifies the changed rule.
	Domain string
	// Old contains the baseline rule for removals and modifications.
	Old *Rule
	// New contains the comparison rule for additions and modifications.
	New *Rule
	// Change identifies the difference kind.
	Change Change
}

// ruleKey identifies a rewrite rule by its domain and answer.
type ruleKey struct {
	domain string
	answer string
}

const (
	// ChangeAdded identifies a rule present only in the comparison set.
	ChangeAdded Change = "added"
	// ChangeRemoved identifies a rule present only in the baseline set.
	ChangeRemoved Change = "removed"
	// ChangeModified identifies a rule whose enabled state changed.
	ChangeModified Change = "modified"
)

// DiffRules compares baseline and comparison rewrite rule sets.
//
// Rules are keyed by domain and answer because one domain can contain multiple
// answers. Input order is retained when selecting keys for each difference kind.
//
// Parameters:
//   - baseline: rules treated as the comparison baseline.
//   - comparison: rules treated as the comparison set.
//
// Returns:
//   - Diff: differences grouped by kind in stable input order.
func DiffRules(baseline, comparison []Rule) Diff {
	baselineByKey, baselineKeys := indexRules(baseline)
	comparisonByKey, comparisonKeys := indexRules(comparison)
	keys := mergeRuleKeys(baselineKeys, comparisonKeys)

	var diff Diff

	for _, key := range keys {
		baselineRule, inBaseline := baselineByKey[key]
		comparisonRule, inComparison := comparisonByKey[key]
		appendDiffEntry(&diff, baselineRule, comparisonRule, inBaseline, inComparison)
	}

	return diff
}

// indexRules indexes rules and records their first-occurrence order.
//
// Parameters:
//   - rules: domain rules to index.
//
// Returns:
//   - map[ruleKey]Rule: the last rule recorded for each key.
//   - []ruleKey: unique keys in first-occurrence order.
func indexRules(rules []Rule) (map[ruleKey]Rule, []ruleKey) {
	indexed := make(map[ruleKey]Rule, len(rules))
	keys := make([]ruleKey, 0, len(rules))

	for _, rule := range rules {
		key := ruleKey{domain: ruleDomain(rule), answer: ruleAnswer(rule)}
		if _, exists := indexed[key]; !exists {
			keys = append(keys, key)
		}

		indexed[key] = rule
	}

	return indexed, keys
}

// mergeRuleKeys combines baseline and comparison keys in stable input order.
//
// Parameters:
//   - baseline: keys derived from the baseline rule set.
//   - comparison: keys derived from the comparison rule set.
//
// Returns:
//   - []ruleKey: unique keys in baseline-then-comparison order.
func mergeRuleKeys(baseline, comparison []ruleKey) []ruleKey {
	keys := make([]ruleKey, 0, len(baseline)+len(comparison))
	seen := make(map[ruleKey]struct{}, len(baseline)+len(comparison))

	for _, key := range baseline {
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	for _, key := range comparison {
		if _, exists := seen[key]; exists {
			continue
		}

		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	return keys
}

// appendDiffEntry appends the difference represented by two indexed rules.
//
// Parameters:
//   - diff: difference set receiving the matching entry.
//   - baselineRule: indexed baseline rule, meaningful when inBaseline is true.
//   - comparisonRule: indexed comparison rule, meaningful when inComparison is
//     true.
//   - inBaseline: reports whether the key exists in the baseline set.
//   - inComparison: reports whether the key exists in the comparison set.
func appendDiffEntry(
	diff *Diff,
	baselineRule, comparisonRule Rule,
	inBaseline, inComparison bool,
) {
	modified := inBaseline && inComparison &&
		ruleEnabled(baselineRule) != ruleEnabled(comparisonRule)

	switch {
	case inBaseline && !inComparison:
		diff.Removed = append(diff.Removed, DiffEntry{
			Domain: ruleDomain(baselineRule),
			Old:    &baselineRule,
			Change: ChangeRemoved,
		})
	case !inBaseline && inComparison:
		diff.Added = append(diff.Added, DiffEntry{
			Domain: ruleDomain(comparisonRule),
			New:    &comparisonRule,
			Change: ChangeAdded,
		})
	case modified:
		diff.Modified = append(diff.Modified, DiffEntry{
			Domain: ruleDomain(comparisonRule),
			Old:    &baselineRule,
			New:    &comparisonRule,
			Change: ChangeModified,
		})
	default:
	}
}

// ruleDomain returns a rule domain or an empty string when absent.
//
// Parameters:
//   - rule: domain rule to read.
//
// Returns:
//   - string: the rule domain, or an empty string when absent.
func ruleDomain(rule Rule) string {
	if rule.Domain == nil {
		return ""
	}

	return *rule.Domain
}

// ruleAnswer returns a rule answer or an empty string when absent.
//
// Parameters:
//   - rule: domain rule to read.
//
// Returns:
//   - string: the rule answer, or an empty string when absent.
func ruleAnswer(rule Rule) string {
	if rule.Answer == nil {
		return ""
	}

	return *rule.Answer
}

// ruleEnabled reports whether a rule is explicitly enabled.
//
// Parameters:
//   - rule: domain rule to read.
//
// Returns:
//   - bool: true only when the rule carries an explicit true value.
func ruleEnabled(rule Rule) bool {
	return rule.Enabled != nil && *rule.Enabled
}
