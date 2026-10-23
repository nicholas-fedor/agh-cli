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

	"github.com/nicholas-fedor/agh-cli/internal/client"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

// TestClientManagementListContinuesAfterFailure verifies all target failures are
// retained and the surviving result is still returned.
func TestClientManagementListContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("list unavailable")
	badService := mockAdguard.NewMockClientsService(t)
	badService.EXPECT().ClientsStatus(mock.Anything).Return(nil, wantErr).Once()

	goodService := mockAdguard.NewMockClientsService(t)
	goodService.EXPECT().ClientsStatus(mock.Anything).Return(&adguard.ClientsStatus{
		Clients: []adguard.ClientConfig{{Name: testClientName}},
	}, nil).Once()

	results, err := testClientManagement(t, map[string]*mockAdguard.MockClientsService{
		badInstance:  badService,
		goodInstance: goodService,
	}).List(testInstancesContext(t), Selection{
		Names: []string{badInstance, goodInstance},
	})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []ClientListResult{{
		Instance:      goodInstance,
		Rows:          []client.Row{{Name: testClientName, Automatic: false}},
		InstanceCount: 2,
	}}, results)
}

// TestClientManagementListUsesConfigurationOrder verifies instances are listed
// in configuration order.
func TestClientManagementListUsesConfigurationOrder(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	calls := make([]string, 0, 2)
	newService := func(name string) *mockAdguard.MockClientsService {
		service := mockAdguard.NewMockClientsService(t)
		service.EXPECT().ClientsStatus(mock.Anything).RunAndReturn(
			func(context.Context) (*adguard.ClientsStatus, error) {
				mutex.Lock()

				calls = append(calls, name)
				mutex.Unlock()

				return &adguard.ClientsStatus{}, nil
			},
		).Once()

		return service
	}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configData := fmt.Appendf(
		nil,
		"instances:\n  %s:\n    host: %s\n  %s:\n    host: %s\n",
		zuluInstance,
		testZuluHost,
		alphaInstance,
		testAlphaHost,
	)
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))

	management := wireClientManagement(func(cfg instance.Config) (adguard.ClientsService, error) {
		return newService(cfg.Name), nil
	}, nil)
	results, err := management.List(contextWithConfigFile(t.Context(), t, configPath), Selection{
		All: true,
	})

	require.NoError(t, err)
	assert.Equal(t, []ClientListResult{
		{Instance: zuluInstance, InstanceCount: 2},
		{Instance: alphaInstance, InstanceCount: 2},
	}, results)
	assert.Equal(t, []string{zuluInstance, alphaInstance}, calls)
}

// TestClientManagementAddContinuesAfterFailure verifies partial success output data is retained.
func TestClientManagementAddContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("add unavailable")
	badService := mockAdguard.NewMockClientsService(t)
	badService.EXPECT().ClientsAdd(mock.Anything, mock.Anything).Return(wantErr).Once()

	goodService := mockAdguard.NewMockClientsService(t)
	goodService.EXPECT().ClientsAdd(mock.Anything, mock.Anything).Return(nil).Once()

	results, err := testClientManagement(t, map[string]*mockAdguard.MockClientsService{
		badInstance:  badService,
		goodInstance: goodService,
	}).Add(testInstancesContext(t), Selection{
		Names: []string{badInstance, goodInstance},
	}, client.Settings{Name: testClientName, IDs: []string{testClientID}})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []MutationResult{{
		Instance: goodInstance,
		Message:  addedClientMessage,
	}}, results)
}

// TestClientManagementUpdatePreservesExplicitFalse verifies app-to-service false update semantics.
func TestClientManagementUpdatePreservesExplicitFalse(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsUpdate(mock.Anything, adguard.ClientUpdate{
		Name: testClientName,
		Data: &adguard.ClientUpdateData{
			Name:                new(testClientName),
			UseGlobalSettings:   new(false),
			FilteringEnabled:    new(false),
			ParentalEnabled:     new(true),
			SafebrowsingEnabled: new(false),
		},
	}).Return(nil).Once()

	results, err := testClientManagement(t, map[string]*mockAdguard.MockClientsService{
		goodInstance: service,
	}).Update(testInstancesContext(t), Selection{
		Names: []string{goodInstance},
	}, client.Settings{
		Name:                testClientName,
		ParentalEnabled:     true,
		UseGlobalSettings:   false,
		FilteringEnabled:    false,
		SafebrowsingEnabled: false,
	})

	require.NoError(t, err)
	assert.Equal(t, []MutationResult{{
		Instance: goodInstance,
		Message:  "Updated client desk",
	}}, results)
}

// TestClientManagementCancellationStopsRemainingTargets verifies cancellation prevents later requests.
func TestClientManagementCancellationStopsRemainingTargets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(testInstancesContext(t))
	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsStatus(mock.Anything).RunAndReturn(
		func(context.Context) (*adguard.ClientsStatus, error) {
			cancel()

			return nil, context.Canceled
		},
	).Once()

	factoryCalls := 0
	management := wireClientManagement(func(_ instance.Config) (adguard.ClientsService, error) {
		factoryCalls++

		return service, nil
	}, nil)

	results, err := management.List(ctx, Selection{
		All: true,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, results)
	assert.Equal(t, 1, factoryCalls)
}

// TestClientManagementUsesExplicitFirstOccurrenceOrder verifies target execution order.
func TestClientManagementUsesExplicitFirstOccurrenceOrder(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	calls := make([]string, 0, 2)
	management := wireClientManagement(func(cfg instance.Config) (adguard.ClientsService, error) {
		service := mockAdguard.NewMockClientsService(t)
		service.EXPECT().ClientsAdd(mock.Anything, mock.Anything).RunAndReturn(
			func(context.Context, adguard.ClientConfig) error {
				mutex.Lock()

				calls = append(calls, cfg.Name)
				mutex.Unlock()

				return nil
			},
		).Once()

		return service, nil
	}, nil)

	results, err := management.Add(testInstancesContext(t), Selection{
		Names: []string{zuluInstance, alphaInstance, zuluInstance},
	}, client.Settings{Name: testClientName, IDs: []string{testClientID}})

	require.NoError(t, err)
	assert.Equal(t, []MutationResult{
		{Instance: zuluInstance, Message: addedClientMessage},
		{Instance: alphaInstance, Message: addedClientMessage},
	}, results)
	assert.Equal(t, []string{zuluInstance, alphaInstance}, calls)
}

// testClientManagement creates management wired to generated service mocks.
//
// Parameters:
//   - services: mock services keyed by instance name.
//
// Returns:
//   - *ClientManagement: management resolving one mock per instance name.
func testClientManagement(
	t *testing.T,
	services map[string]*mockAdguard.MockClientsService,
) *ClientManagement {
	t.Helper()

	return wireClientManagement(func(cfg instance.Config) (adguard.ClientsService, error) {
		service, ok := services[cfg.Name]
		if !ok {
			return nil, fmt.Errorf("unexpected instance %q", cfg.Name)
		}

		return service, nil
	}, nil)
}
