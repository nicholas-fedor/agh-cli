// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

const (
	// FilteringTestAlphaInstance identifies the alpha filtering test instance.
	filteringTestAlphaInstance = "filtering-alpha"
	// FilteringTestBadInstance identifies the failing filtering test instance.
	filteringTestBadInstance = "filtering-bad"
	// FilteringTestGoodInstance identifies the successful filtering test instance.
	filteringTestGoodInstance = "filtering-good"
	// FilteringTestZuluInstance identifies the zulu filtering test instance.
	filteringTestZuluInstance = "filtering-zulu"
	// FilteringTestAddedMessage is the expected add-URL success message.
	filteringTestAddedMessage = "Added filter URL filters"
)

// TestFilteringManagementStatusContinuesAfterFailure verifies partial status results survive failures.
func TestFilteringManagementStatusContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("status unavailable")
	badService := mockAdguard.NewMockFilteringService(t)
	badService.EXPECT().FilteringStatus(mock.Anything).Return(nil, wantErr).Once()

	goodService := mockAdguard.NewMockFilteringService(t)
	goodService.EXPECT().FilteringStatus(mock.Anything).Return(&adguard.FilteringStatus{}, nil).Once()

	results, err := testFilteringManagement(t, map[string]*mockAdguard.MockFilteringService{
		filteringTestBadInstance:  badService,
		filteringTestGoodInstance: goodService,
	}).Status(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names:     []string{filteringTestBadInstance, filteringTestGoodInstance},
	})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []FilteringStatusResult{{
		Instance:      filteringTestGoodInstance,
		Index:         1,
		InstanceCount: 2,
	}}, results)
}

// TestFilteringManagementStatusPreservesEmptyLists verifies app results retain list presence.
func TestFilteringManagementStatusPreservesEmptyLists(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().FilteringStatus(mock.Anything).Return(&adguard.FilteringStatus{
		Filters:          &[]adguard.FilterSubscription{},
		WhitelistFilters: &[]adguard.FilterSubscription{},
	}, nil).Once()

	results, err := testFilteringManagement(t, map[string]*mockAdguard.MockFilteringService{
		filteringTestGoodInstance: service,
	}).Status(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names:     []string{filteringTestGoodInstance},
	})

	require.NoError(t, err)
	require.Len(t, results, 1)
	require.NotNil(t, results[0].Filters)
	require.NotNil(t, results[0].WhitelistFilters)
	assert.Empty(t, *results[0].Filters)
	assert.Empty(t, *results[0].WhitelistFilters)
}

// TestFilteringManagementStatusUsesConfigurationOrder verifies status request and result order.
func TestFilteringManagementStatusUsesConfigurationOrder(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	calls := make([]string, 0, 2)
	management := &FilteringManagement{newService: func(cfg instance.Config) (adguard.FilteringService, error) {
		service := mockAdguard.NewMockFilteringService(t)
		service.EXPECT().FilteringStatus(mock.Anything).RunAndReturn(
			func(context.Context) (*adguard.FilteringStatus, error) {
				mutex.Lock()

				calls = append(calls, cfg.Name)
				mutex.Unlock()

				return &adguard.FilteringStatus{}, nil
			},
		).Once()

		return service, nil
	}}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configData := fmt.Appendf(
		nil,
		"instances:\n  %s:\n    host: %s\n  %s:\n    host: %s\n",
		filteringTestZuluInstance,
		testZuluHost,
		filteringTestAlphaInstance,
		testAlphaHost,
	)
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))

	results, err := management.Status(t.Context(), FilteringSelection{
		Instances:  filteringTestInstances(),
		All:        true,
		ConfigPath: configPath,
	})

	require.NoError(t, err)
	assert.Equal(t, []FilteringStatusResult{
		{Instance: filteringTestZuluInstance, Index: 0, InstanceCount: 2},
		{Instance: filteringTestAlphaInstance, Index: 1, InstanceCount: 2},
	}, results)
	assert.Equal(t, []string{filteringTestZuluInstance, filteringTestAlphaInstance}, calls)
}

// TestFilteringManagementUpdateConfigPreservesFalseAndZero verifies app-to-domain values.
func TestFilteringManagementUpdateConfigPreservesFalseAndZero(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().UpdateFilteringConfig(mock.Anything, adguard.FilteringConfig{
		Enabled:  new(false),
		Interval: new(int64(0)),
	}).Return(nil).Once()

	results, err := testFilteringManagement(t, map[string]*mockAdguard.MockFilteringService{
		filteringTestGoodInstance: service,
	}).UpdateConfig(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names:     []string{filteringTestGoodInstance},
	}, false, 0)

	require.NoError(t, err)
	assert.Equal(t, []FilteringMutationResult{{
		Instance: filteringTestGoodInstance,
		Message:  "Filtering config updated: enabled=false, interval=0",
	}}, results)
}

// TestFilteringManagementAddURLPreservesEmptyAndFalse verifies app-to-domain values.
func TestFilteringManagementAddURLPreservesEmptyAndFalse(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().AddFilteringURL(mock.Anything, adguard.AddFilteringURLRequest{
		Name:      new(""),
		URL:       new(""),
		Whitelist: new(false),
	}).Return(nil).Once()

	results, err := testFilteringManagement(t, map[string]*mockAdguard.MockFilteringService{
		filteringTestGoodInstance: service,
	}).AddURL(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names:     []string{filteringTestGoodInstance},
	}, "", "", false)

	require.NoError(t, err)
	assert.Equal(t, []FilteringMutationResult{{
		Instance: filteringTestGoodInstance,
		Message:  "Added filter URL ",
	}}, results)
}

// TestFilteringManagementRemoveURLPreservesFalse verifies remove request shaping.
func TestFilteringManagementRemoveURLPreservesFalse(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().RemoveFilteringURL(mock.Anything, adguard.RemoveFilteringURLRequest{
		URL:       new(""),
		Whitelist: new(false),
	}).Return(nil).Once()

	results, err := testFilteringManagement(t, map[string]*mockAdguard.MockFilteringService{
		filteringTestGoodInstance: service,
	}).RemoveURL(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names:     []string{filteringTestGoodInstance},
	}, "")

	require.NoError(t, err)
	assert.Equal(t, []FilteringMutationResult{{
		Instance: filteringTestGoodInstance,
		Message:  "Removed filter URL ",
	}}, results)
}

// TestFilteringManagementMutationContinuesAfterFailure verifies partial mutation results.
func TestFilteringManagementMutationContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("add unavailable")
	badService := mockAdguard.NewMockFilteringService(t)
	badService.EXPECT().AddFilteringURL(mock.Anything, mock.Anything).Return(wantErr).Once()

	goodService := mockAdguard.NewMockFilteringService(t)
	goodService.EXPECT().AddFilteringURL(mock.Anything, mock.Anything).Return(nil).Once()

	results, err := testFilteringManagement(t, map[string]*mockAdguard.MockFilteringService{
		filteringTestBadInstance:  badService,
		filteringTestGoodInstance: goodService,
	}).AddURL(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names:     []string{filteringTestBadInstance, filteringTestGoodInstance},
	}, "filters", "https://filters.example/list.txt", false)

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []FilteringMutationResult{{
		Instance: filteringTestGoodInstance,
		Message:  filteringTestAddedMessage,
	}}, results)
}

// TestFilteringManagementCancellationStopsRemainingTargets verifies cancellation stops the run.
func TestFilteringManagementCancellationStopsRemainingTargets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().FilteringStatus(mock.Anything).RunAndReturn(
		func(context.Context) (*adguard.FilteringStatus, error) {
			cancel()

			return nil, context.Canceled
		},
	).Once()

	factoryCalls := 0
	management := &FilteringManagement{newService: func(_ instance.Config) (adguard.FilteringService, error) {
		factoryCalls++

		return service, nil
	}}

	results, err := management.Status(ctx, FilteringSelection{
		Instances: filteringTestInstances(),
		All:       true,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, results)
	assert.Equal(t, 1, factoryCalls)
}

// TestFilteringManagementUsesExplicitFirstOccurrenceOrder verifies mutation request order.
func TestFilteringManagementUsesExplicitFirstOccurrenceOrder(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	calls := make([]string, 0, 2)
	management := &FilteringManagement{newService: func(cfg instance.Config) (adguard.FilteringService, error) {
		service := mockAdguard.NewMockFilteringService(t)
		service.EXPECT().AddFilteringURL(mock.Anything, mock.Anything).RunAndReturn(
			func(context.Context, adguard.AddFilteringURLRequest) error {
				mutex.Lock()

				calls = append(calls, cfg.Name)
				mutex.Unlock()

				return nil
			},
		).Once()

		return service, nil
	}}

	results, err := management.AddURL(t.Context(), FilteringSelection{
		Instances: filteringTestInstances(),
		Names: []string{
			filteringTestZuluInstance,
			filteringTestAlphaInstance,
			filteringTestZuluInstance,
		},
	}, "filters", "https://filters.example/list.txt", false)

	require.NoError(t, err)
	assert.Equal(t, []FilteringMutationResult{
		{Instance: filteringTestZuluInstance, Message: filteringTestAddedMessage},
		{Instance: filteringTestAlphaInstance, Message: filteringTestAddedMessage},
	}, results)
	assert.Equal(t, []string{filteringTestZuluInstance, filteringTestAlphaInstance}, calls)
}

// testFilteringManagement creates app wiring backed by generated filtering mocks.
//
// Parameters:
//   - services: mock services keyed by instance name.
//
// Returns:
//   - *FilteringManagement: management resolving one mock per instance name.
func testFilteringManagement(
	t *testing.T,
	services map[string]*mockAdguard.MockFilteringService,
) *FilteringManagement {
	t.Helper()

	return &FilteringManagement{newService: func(cfg instance.Config) (adguard.FilteringService, error) {
		service, ok := services[cfg.Name]
		if !ok {
			return nil, fmt.Errorf("unexpected instance %q", cfg.Name)
		}

		return service, nil
	}}
}

// filteringTestInstances returns the instance source for filtering tests.
//
// Returns:
//   - instance.Source: instance mappings for the shared filtering instances.
func filteringTestInstances() instance.Source {
	return instance.Source{
		filteringTestAlphaInstance: map[string]any{
			testHostKey: testAlphaHost,
		},
		filteringTestBadInstance: map[string]any{
			testHostKey: testBadHost,
		},
		filteringTestGoodInstance: map[string]any{
			testHostKey: testGoodHost,
		},
		filteringTestZuluInstance: map[string]any{
			testHostKey: testZuluHost,
		},
	}
}
