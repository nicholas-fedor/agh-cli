// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package execution_test

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/execution"
	mockExecution "github.com/nicholas-fedor/agh-cli/internal/execution/mocks"
)

// TestRunWithGeneratedOperationMockPreservesOrderAndContinuesAfterFailure verifies
// sequential execution and failure aggregation through the generated operation mock.
func TestRunWithGeneratedOperationMockPreservesOrderAndContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	errRejected := errors.New("rejected")
	ctx := t.Context()
	targets := []execution.Target[string]{
		{Name: "first", Value: "one"},
		{Name: "middle", Value: "two"},
		{Name: "last", Value: "three"},
	}
	expectedNames := make([]string, 0, len(targets))

	for _, target := range targets {
		expectedNames = append(expectedNames, target.Name)
	}

	operation := mockExecution.NewMockOperation[string](t)
	firstCall := operation.EXPECT().Execute(ctx, targets[0]).Return(nil).Once()
	middleCall := operation.EXPECT().Execute(ctx, targets[1]).Return(errRejected).Once()
	lastCall := operation.EXPECT().Execute(ctx, targets[2]).Return(nil).Once()
	mock.InOrder(firstCall, middleCall, lastCall)

	report := execution.Run(ctx, targets, operation)

	reportErr := report.Err()
	require.ErrorIs(t, reportErr, errRejected)

	aggregate, ok := errors.AsType[execution.AggregateError[string]](reportErr)
	require.True(t, ok)
	require.Len(t, report, len(targets))
	require.Len(t, aggregate, 1)
	assert.Equal(t, expectedNames, targetNames(report))
	assert.Equal(t, []string{targets[1].Name}, targetNames(execution.Report[string](aggregate)))
	assert.True(t, report[0].Attempted)
	assert.True(t, report[1].Attempted)
	assert.True(t, report[2].Attempted)
	require.NoError(t, report[0].Err)
	require.ErrorIs(t, report[1].Err, errRejected)
	require.NoError(t, report[2].Err)
}

// targetNames returns target names in report order.
func targetNames(report execution.Report[string]) []string {
	names := make([]string, 0, len(report))
	for _, outcome := range report {
		names = append(names, outcome.Target.Name)
	}

	return names
}
