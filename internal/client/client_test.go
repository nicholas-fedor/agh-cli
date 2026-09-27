// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

const (
	// ClientTestName is the configured client name used in client tests.
	clientTestName = "desk"
	// ClientTestID is the client identifier used in client tests.
	clientTestID = "192.0.2.10"
	// ClientTestAutoName is the automatically discovered client name used in client tests.
	clientTestAutoName = "phone"
)

// TestServiceListShapesRows verifies configured and discovered client result shaping.
func TestServiceListShapesRows(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsStatus(mock.Anything).Return(&adguard.ClientsStatus{
		Clients:     []adguard.ClientConfig{{Name: clientTestName}},
		AutoClients: []adguard.ClientAuto{{Name: clientTestAutoName}},
	}, nil).Once()

	result, err := NewService(service).List(t.Context())

	require.NoError(t, err)
	assert.Equal(t, []Row{
		{Name: clientTestName, Automatic: false},
		{Name: clientTestAutoName, Automatic: true},
	}, result.Rows)
}

// TestServiceAddShapesRequest verifies add request shaping.
func TestServiceAddShapesRequest(t *testing.T) {
	t.Parallel()

	request := AddRequest{
		Name:                clientTestName,
		IDs:                 []string{clientTestID},
		UseGlobalSettings:   true,
		FilteringEnabled:    true,
		ParentalEnabled:     false,
		SafebrowsingEnabled: true,
	}
	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsAdd(mock.Anything, adguard.ClientConfig{
		Name:                     clientTestName,
		IDs:                      []string{clientTestID},
		UseGlobalSettings:        true,
		FilteringEnabled:         true,
		ParentalEnabled:          false,
		SafebrowsingEnabled:      true,
		SafesearchEnabled:        false,
		SafeSearch:               nil,
		UseGlobalBlockedServices: false,
		BlockedServicesSchedule:  nil,
		BlockedServices:          nil,
		Upstreams:                nil,
		Tags:                     nil,
		IgnoreQuerylog:           false,
		IgnoreStatistics:         false,
		UpstreamsCacheEnabled:    false,
		UpstreamsCacheSize:       0,
	}).Return(nil).Once()

	require.NoError(t, NewService(service).Add(t.Context(), request))
}

// TestServiceDeleteShapesRequest verifies delete request shaping.
func TestServiceDeleteShapesRequest(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsDelete(mock.Anything, adguard.ClientDelete{Name: clientTestName}).
		Return(nil).
		Once()

	require.NoError(t, NewService(service).Delete(t.Context(), DeleteRequest{Name: clientTestName}))
}

// TestServiceUpdatePreservesExplicitFalse verifies false update values remain present.
func TestServiceUpdatePreservesExplicitFalse(t *testing.T) {
	t.Parallel()

	request := UpdateRequest{
		Name:                clientTestName,
		IDs:                 []string{clientTestID},
		UseGlobalSettings:   false,
		FilteringEnabled:    false,
		ParentalEnabled:     true,
		SafebrowsingEnabled: false,
	}
	service := mockAdguard.NewMockClientsService(t)
	service.EXPECT().ClientsUpdate(mock.Anything, adguard.ClientUpdate{
		Name: clientTestName,
		Data: &adguard.ClientUpdateData{
			Name:                new(clientTestName),
			IDs:                 new([]string{clientTestID}),
			UseGlobalSettings:   new(false),
			FilteringEnabled:    new(false),
			ParentalEnabled:     new(true),
			SafebrowsingEnabled: new(false),
		},
	}).Return(nil).Once()

	require.NoError(t, NewService(service).Update(t.Context(), request))
}

// TestServicePropagatesOperationErrors verifies use cases preserve service failures.
func TestServicePropagatesOperationErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("service unavailable")

	t.Run("list", func(t *testing.T) {
		t.Parallel()

		service := mockAdguard.NewMockClientsService(t)
		service.EXPECT().ClientsStatus(mock.Anything).Return(nil, wantErr).Once()

		_, err := NewService(service).List(t.Context())

		require.ErrorIs(t, err, wantErr)
	})

	t.Run("add", func(t *testing.T) {
		t.Parallel()

		service := mockAdguard.NewMockClientsService(t)
		service.EXPECT().ClientsAdd(mock.Anything, mock.Anything).Return(wantErr).Once()

		err := NewService(service).Add(t.Context(), AddRequest{Name: clientTestName})

		require.ErrorIs(t, err, wantErr)
	})

	t.Run("delete", func(t *testing.T) {
		t.Parallel()

		service := mockAdguard.NewMockClientsService(t)
		service.EXPECT().ClientsDelete(mock.Anything, mock.Anything).Return(wantErr).Once()

		err := NewService(service).Delete(t.Context(), DeleteRequest{Name: clientTestName})

		require.ErrorIs(t, err, wantErr)
	})

	t.Run("update", func(t *testing.T) {
		t.Parallel()

		service := mockAdguard.NewMockClientsService(t)
		service.EXPECT().ClientsUpdate(mock.Anything, mock.Anything).Return(wantErr).Once()

		err := NewService(service).Update(t.Context(), UpdateRequest{Name: clientTestName})

		require.ErrorIs(t, err, wantErr)
	})
}
