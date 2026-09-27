// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package execution

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// FirstTarget identifies the first ordered test target.
	firstTarget = "first"
	// MiddleTarget identifies the failing middle test target.
	middleTarget = "middle"
	// LastTarget identifies the last ordered test target.
	lastTarget = "last"
)

// TestRunContinuesAfterCallbackReturnsCancellationError verifies that an
// operation error equal to [context.Canceled] does not itself stop later targets.
func TestRunContinuesAfterCallbackReturnsCancellationError(t *testing.T) {
	t.Parallel()

	called := make([]string, 0, 3)
	report := Run(t.Context(), orderedStringTargets(),
		AdaptOperation[string](func(_ context.Context, target Target[string]) error {
			called = append(called, target.Name)
			if target.Name == middleTarget {
				return context.Canceled
			}

			return nil
		}),
	)

	assert.Equal(t, []string{firstTarget, middleTarget, lastTarget}, called)
	require.ErrorIs(t, report.Err(), context.Canceled)
}

// TestRunStopsWhenOperationCancelsContext verifies that parent cancellation
// prevents execution of targets that have not started.
func TestRunStopsWhenOperationCancelsContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	called := make([]string, 0, 3)

	report := Run(ctx, orderedStringTargets(),
		AdaptOperation[string](func(_ context.Context, target Target[string]) error {
			called = append(called, target.Name)
			if target.Name == middleTarget {
				cancel()

				return context.Canceled
			}

			return nil
		}),
	)

	assert.Equal(t, []string{firstTarget, middleTarget}, called)
	require.ErrorIs(t, report.Err(), context.Canceled)
	assert.Equal(
		t,
		[]string{firstTarget, middleTarget, lastTarget},
		outcomeNames(report),
	)
	assert.True(t, report[1].Attempted)
	assert.False(t, report[2].Attempted)
}

// TestRunStopsBeforeRemainingTargetsAfterSuccessfulCancellation verifies the
// unattempted cancellation outcome after an operation cancels its context.
func TestRunStopsBeforeRemainingTargetsAfterSuccessfulCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	called := make([]string, 0, 3)

	report := Run(ctx, orderedStringTargets(),
		AdaptOperation[string](func(_ context.Context, target Target[string]) error {
			called = append(called, target.Name)
			if target.Name == firstTarget {
				cancel()
			}

			return nil
		}),
	)

	assert.Equal(t, []string{firstTarget}, called)
	require.ErrorIs(t, report.Err(), context.Canceled)
	assert.Equal(t, []string{firstTarget, middleTarget}, outcomeNames(report))
	assert.True(t, report[0].Attempted)
	assert.False(t, report[1].Attempted)
	require.ErrorIs(t, report[1].Err, context.Canceled)
}

// TestRunDoesNotReportLateCancellationAfterLastTarget verifies that Run does
// not perform another cancellation check after the final target completes.
func TestRunDoesNotReportLateCancellationAfterLastTarget(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	report := Run(ctx, []Target[string]{{Name: "only", Value: "value"}},
		AdaptOperation[string](func(_ context.Context, _ Target[string]) error {
			cancel()

			return nil
		}),
	)

	require.NoError(t, report.Err())
	assert.Len(t, report, 1)
}

// TestRunWithAlreadyCancelledContextAttemptsNoTargets verifies preflight
// cancellation without invoking the operation.
func TestRunWithAlreadyCancelledContextAttemptsNoTargets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	called := make([]string, 0, 3)

	report := Run(ctx, orderedStringTargets(),
		AdaptOperation[string](func(_ context.Context, target Target[string]) error {
			called = append(called, target.Name)

			return nil
		}),
	)

	assert.Empty(t, called)
	require.ErrorIs(t, report.Err(), context.Canceled)
	assert.Equal(t, firstTarget, report[0].Target.Name)
}

// TestRunWithNoTargetsSucceeds verifies that an empty run invokes no operation.
func TestRunWithNoTargetsSucceeds(t *testing.T) {
	t.Parallel()

	report := Run(t.Context(), []Target[string]{}, operationMustNotRun(t))

	assert.Empty(t, report)
	require.NoError(t, report.Err())
}

// orderedStringTargets returns three fully populated ordered targets.
//
// Returns:
//   - []Target: targets named first, middle, and last.
func orderedStringTargets() []Target[string] {
	return []Target[string]{
		{Name: firstTarget, Value: "one"},
		{Name: middleTarget, Value: "two"},
		{Name: lastTarget, Value: "three"},
	}
}

// outcomeNames returns target names in outcome order.
//
// Parameters:
//   - report: outcomes whose target names are requested.
//
// Returns:
//   - []string: target names in report order.
func outcomeNames(report Report[string]) []string {
	names := make([]string, 0, len(report))
	for _, outcome := range report {
		names = append(names, outcome.Target.Name)
	}

	return names
}

// operationMustNotRun returns an operation that fails the test if invoked.
//
// Returns:
//   - Operation: an operation that must not execute.
func operationMustNotRun(t *testing.T) Operation[string] {
	t.Helper()

	return AdaptOperation[string](func(_ context.Context, _ Target[string]) error {
		require.FailNow(t, "operation must not run")

		return nil
	})
}
