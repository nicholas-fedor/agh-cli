// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
)

// RewriteDiffMode identifies how a rewrite diff was computed.
type RewriteDiffMode uint8

// RewriteDiffEntry contains display-ready values for one rewrite difference.
type RewriteDiffEntry struct {
	// Domain identifies the changed rule.
	Domain string
	// Old contains the baseline display rule when present.
	Old *RewriteRule
	// New contains the comparison display rule when present.
	New *RewriteRule
	// Change identifies the difference kind.
	Change string
}

// RewriteDiff contains display-ready rewrite differences.
type RewriteDiff struct {
	// Added contains rules present only in the comparison set.
	Added []RewriteDiffEntry
	// Removed contains rules present only in the baseline set.
	Removed []RewriteDiffEntry
	// Modified contains rules whose enabled state changed.
	Modified []RewriteDiffEntry
}

// RewriteDiffResult contains one completed rewrite diff.
type RewriteDiffResult struct {
	// Mode identifies file or instance comparison.
	Mode RewriteDiffMode
	// InstanceNames contains compared instances in display order.
	InstanceNames []string
	// Diff contains the computed differences.
	Diff RewriteDiff
}

const (
	// RewriteDiffFile compares a local file with one instance.
	RewriteDiffFile RewriteDiffMode = iota
	// RewriteDiffInstances compares two configured instances.
	RewriteDiffInstances
)

// RewriteFileInstanceCount is the number of instances required for file diffs.
const rewriteFileInstanceCount = 1

// RewriteComparisonInstanceCount is the number of instances required for instance diffs.
const rewriteComparisonInstanceCount = 2

var (
	// ErrRewriteFileInstanceCount reports invalid file-diff target selection.
	errRewriteFileInstanceCount = errors.New("specify exactly one --instance when using --file")
	// ErrRewriteComparisonInstanceCount reports invalid instance-diff selection.
	errRewriteComparisonInstanceCount = errors.New(
		"specify exactly two --instance flags, or one --instance with --file",
	)
)

// Diff compares a local file or two instances and returns display-ready results.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - filePath: optional local rules file; empty selects instance comparison.
//
// Returns:
//   - RewriteDiffResult: display-ready differences for the comparison mode.
//   - error: a wrapped resolution, selection, or service error.
func (a *RewriteManagement) Diff(
	ctx context.Context,
	selection RewriteSelection,
	filePath string,
) (RewriteDiffResult, error) {
	targets, err := rewriteTargets(ctx, selection, a.resolve)
	if err != nil {
		return RewriteDiffResult{}, fmt.Errorf("resolve rewrite diff targets: %w", err)
	}

	if filePath != "" {
		result, diffErr := a.diffFile(ctx, targets, filePath)
		if diffErr != nil {
			return RewriteDiffResult{}, fmt.Errorf("compare rewrite file: %w", diffErr)
		}

		return result, nil
	}

	result, diffErr := a.diffInstances(ctx, targets)
	if diffErr != nil {
		return RewriteDiffResult{}, fmt.Errorf("compare rewrite instances: %w", diffErr)
	}

	return result, nil
}

// diffFile compares local rules with one configured instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - targets: resolved diff targets; exactly one is required.
//   - filePath: local rules file used as the baseline.
//
// Returns:
//   - RewriteDiffResult: file comparison differences.
//   - error: a wrapped selection, parse, or service error.
func (a *RewriteManagement) diffFile(
	ctx context.Context,
	targets []execution.Target[instance.Config],
	filePath string,
) (RewriteDiffResult, error) {
	if len(targets) != rewriteFileInstanceCount {
		return RewriteDiffResult{}, errRewriteFileInstanceCount
	}

	localRules, err := rewrite.ParseRulesFile(filePath)
	if err != nil {
		return RewriteDiffResult{}, fmt.Errorf("parse rewrite rules file: %w", err)
	}

	target := targets[0]
	remoteRules, err := a.listTarget(ctx, target)
	if err != nil {
		return RewriteDiffResult{}, fmt.Errorf("list rewrite rules for %q: %w", target.Name, err)
	}

	return RewriteDiffResult{
		Mode:          RewriteDiffFile,
		InstanceNames: []string{target.Name},
		Diff:          shapeRewriteDiff(rewrite.DiffRules(localRules, remoteRules)),
	}, nil
}

// diffInstances compares two configured instances in sorted name order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - targets: resolved diff targets; exactly two are required.
//
// Returns:
//   - RewriteDiffResult: instance comparison differences.
//   - error: a wrapped selection, cancellation, or service error.
func (a *RewriteManagement) diffInstances(
	ctx context.Context,
	targets []execution.Target[instance.Config],
) (RewriteDiffResult, error) {
	if len(targets) != rewriteComparisonInstanceCount {
		return RewriteDiffResult{}, errRewriteComparisonInstanceCount
	}

	targets = slices.Clone(targets)
	slices.SortFunc(targets, func(left, right execution.Target[instance.Config]) int {
		return strings.Compare(left.Name, right.Name)
	})

	ruleSets := make([][]rewrite.Rule, 0, len(targets))

	for _, target := range targets {
		err := ctx.Err()
		if err != nil {
			return RewriteDiffResult{}, fmt.Errorf("compare rewrite instances: %w", err)
		}

		rules, err := a.listTarget(ctx, target)
		if err != nil {
			return RewriteDiffResult{}, fmt.Errorf("list rewrite rules for %q: %w", target.Name, err)
		}

		ruleSets = append(ruleSets, rules)
	}

	names := []string{targets[0].Name, targets[1].Name}

	return RewriteDiffResult{
		Mode:          RewriteDiffInstances,
		InstanceNames: names,
		Diff:          shapeRewriteDiff(rewrite.DiffRules(ruleSets[0], ruleSets[1])),
	}, nil
}

// listTarget retrieves and shapes rules for one diff target.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - target: resolved diff target to read.
//
// Returns:
//   - []domainrewrite.Rule: rules reported by the target instance.
//   - error: a wrapped service-construction or listing error.
func (a *RewriteManagement) listTarget(
	ctx context.Context,
	target execution.Target[instance.Config],
) ([]rewrite.Rule, error) {
	service, err := a.useCase(target.Value)
	if err != nil {
		return nil, fmt.Errorf("create rewrite use case for %q: %w", target.Name, err)
	}

	rules, err := service.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rewrite rules for %s: %w", target.Name, err)
	}

	return rules, nil
}

// shapeRewriteDiff converts domain differences into display values.
//
// Parameters:
//   - diff: domain differences keyed by difference kind.
//
// Returns:
//   - RewriteDiff: display differences for each difference kind.
func shapeRewriteDiff(diff rewrite.Diff) RewriteDiff {
	return RewriteDiff{
		Added:    shapeRewriteDiffEntries(diff.Added),
		Removed:  shapeRewriteDiffEntries(diff.Removed),
		Modified: shapeRewriteDiffEntries(diff.Modified),
	}
}

// shapeRewriteDiffEntries converts and copies one domain difference slice.
//
// Parameters:
//   - entries: domain differences; nil stays nil.
//
// Returns:
//   - []RewriteDiffEntry: display differences, or nil for absent input.
func shapeRewriteDiffEntries(entries []rewrite.DiffEntry) []RewriteDiffEntry {
	if entries == nil {
		return nil
	}

	shaped := make([]RewriteDiffEntry, 0, len(entries))
	for _, entry := range entries {
		shaped = append(shaped, RewriteDiffEntry{
			Domain: entry.Domain,
			Old:    shapeRewriteRulePointer(entry.Old),
			New:    shapeRewriteRulePointer(entry.New),
			Change: string(entry.Change),
		})
	}

	return shaped
}

// shapeRewriteRulePointer converts one optional domain rule.
//
// Parameters:
//   - rule: optional domain rule.
//
// Returns:
//   - *RewriteRule: display values, or nil for absent input.
func shapeRewriteRulePointer(rule *rewrite.Rule) *RewriteRule {
	if rule == nil {
		return nil
	}

	shaped := shapeRewriteRule(*rule)

	return &shaped
}
