// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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

// TestClientManagementListContinuesAfterFailure verifies all target failures are retained.
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
	}).List(t.Context(), ClientSelection{
		Instances: testInstances(),
		Names:     []string{badInstance, goodInstance},
	})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []ClientListResult{{
		Instance:      goodInstance,
		Rows:          []client.Row{{Name: testClientName, Automatic: false}},
		Index:         1,
		InstanceCount: 2,
	}}, results)
}

// TestClientManagementListUsesConfigurationOrder verifies output order independently of request order.
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

	management := &ClientManagement{newService: func(cfg instance.Config) (adguard.ClientsService, error) {
		return newService(cfg.Name), nil
	}}
	results, err := management.List(t.Context(), ClientSelection{
		Instances: instance.Source{
			alphaInstance: map[string]any{testHostKey: testAlphaHost},
			zuluInstance:  map[string]any{testHostKey: testZuluHost},
		},
		All:        true,
		ConfigPath: configPath,
	})

	require.NoError(t, err)
	assert.Equal(t, []ClientListResult{
		{Instance: zuluInstance, Index: 1, InstanceCount: 2},
		{Instance: alphaInstance, Index: 0, InstanceCount: 2},
	}, results)
	assert.Equal(t, []string{alphaInstance, zuluInstance}, calls)
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
	}).Add(t.Context(), ClientSelection{
		Instances: testInstances(),
		Names:     []string{badInstance, goodInstance},
	}, ClientMutation{Name: testClientName, IDs: []string{testClientID}})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []ClientMutationResult{{
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
	}).Update(t.Context(), ClientSelection{
		Instances: testInstances(),
		Names:     []string{goodInstance},
	}, ClientMutation{
		Name:                testClientName,
		ParentalEnabled:     true,
		UseGlobalSettings:   false,
		FilteringEnabled:    false,
		SafebrowsingEnabled: false,
	})

	require.NoError(t, err)
	assert.Equal(t, []ClientMutationResult{{
		Instance: goodInstance,
		Message:  "Updated client desk",
	}}, results)
}

// TestClientManagementCancellationStopsRemainingTargets verifies cancellation prevents later requests.
func TestClientManagementCancellationStopsRemainingTargets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsStatus(mock.Anything).RunAndReturn(
		func(context.Context) (*adguard.ClientsStatus, error) {
			cancel()

			return nil, context.Canceled
		},
	).Once()

	factoryCalls := 0
	management := &ClientManagement{newService: func(_ instance.Config) (adguard.ClientsService, error) {
		factoryCalls++

		return service, nil
	}}

	results, err := management.List(ctx, ClientSelection{
		Instances: testInstances(),
		All:       true,
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
	management := &ClientManagement{newService: func(cfg instance.Config) (adguard.ClientsService, error) {
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
	}}

	results, err := management.Add(t.Context(), ClientSelection{
		Instances: testInstances(),
		Names:     []string{zuluInstance, alphaInstance, zuluInstance},
	}, ClientMutation{Name: testClientName, IDs: []string{testClientID}})

	require.NoError(t, err)
	assert.Equal(t, []ClientMutationResult{
		{Instance: zuluInstance, Message: addedClientMessage},
		{Instance: alphaInstance, Message: addedClientMessage},
	}, results)
	assert.Equal(t, []string{zuluInstance, alphaInstance}, calls)
}

// TestNewAdguardClientsServiceUsesInstanceSettings verifies production service wiring.
func TestNewAdguardClientsServiceUsesInstanceSettings(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/clients", r.URL.Path)

		username, password, authenticated := r.BasicAuth()
		assert.True(t, authenticated)
		assert.Equal(t, "user", username)
		assert.Equal(t, "pass", password)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`{"clients":[]}`))
		assert.NoError(t, err)
	}))

	httpClient := server.Client()

	service, err := newAdguardClientsServiceWithHTTPClient(instance.Config{
		Name:       goodInstance,
		Host:       "127.0.0.1",
		Scheme:     "http",
		Username:   "user",
		Password:   "pass",
		Credential: nil,
	}, httpClient)
	require.NoError(t, err)

	status, err := service.ClientsStatus(t.Context())

	require.NoError(t, err)
	assert.Empty(t, status.Clients)
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

	return &ClientManagement{newService: func(cfg instance.Config) (adguard.ClientsService, error) {
		service, ok := services[cfg.Name]
		if !ok {
			return nil, fmt.Errorf("unexpected instance %q", cfg.Name)
		}

		return service, nil
	}}
}
