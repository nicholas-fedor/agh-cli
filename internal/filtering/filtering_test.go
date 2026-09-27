// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

// TestServiceUpdateConfigPreservesFalseAndZero verifies explicit config values remain present.
func TestServiceUpdateConfigPreservesFalseAndZero(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().UpdateFilteringConfig(mock.Anything, adguard.FilteringConfig{
		Enabled:  new(false),
		Interval: new(int64(0)),
	}).Return(nil).Once()

	err := NewService(service).UpdateConfig(t.Context(), ConfigRequest{
		Enabled:  false,
		Interval: 0,
	})

	require.NoError(t, err)
}

// TestServiceAddURLPreservesEmptyAndFalse verifies explicit add values remain present.
func TestServiceAddURLPreservesEmptyAndFalse(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().AddFilteringURL(mock.Anything, adguard.AddFilteringURLRequest{
		Name:      new(""),
		URL:       new(""),
		Whitelist: new(false),
	}).Return(nil).Once()

	err := NewService(service).AddURL(t.Context(), URLRequest{})

	require.NoError(t, err)
}

// TestServiceRemoveURLPreservesEmptyAndFalse verifies explicit remove values remain present.
func TestServiceRemoveURLPreservesEmptyAndFalse(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().RemoveFilteringURL(mock.Anything, adguard.RemoveFilteringURLRequest{
		URL:       new(""),
		Whitelist: new(false),
	}).Return(nil).Once()

	err := NewService(service).RemoveURL(t.Context(), URLRequest{})

	require.NoError(t, err)
}

// TestServiceStatusPreservesResponsePresence verifies status shaping retains optional values.
func TestServiceStatusPreservesResponsePresence(t *testing.T) {
	t.Parallel()

	updated := time.Date(2026, time.September, 25, 12, 0, 0, 0, time.UTC)
	status := &adguard.FilteringStatus{
		Enabled:  new(false),
		Interval: new(int64(0)),
		Filters: &[]adguard.FilterSubscription{{
			Enabled:     false,
			ID:          1,
			LastUpdated: &updated,
			Name:        "filters",
			RulesCount:  0,
			URL:         "https://filters.example/list.txt",
		}},
		WhitelistFilters: &[]adguard.FilterSubscription{},
		UserRules:        &[]string{},
	}
	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().FilteringStatus(mock.Anything).Return(status, nil).Once()

	result, err := NewService(service).Status(t.Context())

	require.NoError(t, err)
	assert.Equal(t, Status{
		Enabled:  new(false),
		Interval: new(int64(0)),
		Filters: &[]Subscription{{
			Enabled:     false,
			ID:          1,
			LastUpdated: &updated,
			Name:        "filters",
			RulesCount:  0,
			URL:         "https://filters.example/list.txt",
		}},
		WhitelistFilters: &[]Subscription{},
		UserRules:        &[]string{},
	}, result)
}

// TestServicePropagatesOperationErrors verifies use cases retain service failures.
func TestServicePropagatesOperationErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("filtering unavailable")
	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().FilteringStatus(mock.Anything).Return(nil, wantErr).Once()
	service.EXPECT().UpdateFilteringConfig(mock.Anything, mock.Anything).Return(wantErr).Once()
	service.EXPECT().AddFilteringURL(mock.Anything, mock.Anything).Return(wantErr).Once()
	service.EXPECT().RemoveFilteringURL(mock.Anything, mock.Anything).Return(wantErr).Once()

	filtering := NewService(service)
	_, statusErr := filtering.Status(t.Context())
	configErr := filtering.UpdateConfig(t.Context(), ConfigRequest{})
	addErr := filtering.AddURL(t.Context(), URLRequest{})
	removeErr := filtering.RemoveURL(t.Context(), URLRequest{})

	require.ErrorIs(t, statusErr, wantErr)
	require.ErrorIs(t, configErr, wantErr)
	require.ErrorIs(t, addErr, wantErr)
	require.ErrorIs(t, removeErr, wantErr)
}

// TestServicePreservesCancellation verifies cancellation reaches the public service unchanged.
func TestServicePreservesCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().FilteringStatus(mock.Anything).RunAndReturn(
		func(ctx context.Context) (*adguard.FilteringStatus, error) {
			return nil, ctx.Err()
		},
	).Once()

	_, err := NewService(service).Status(ctx)

	require.ErrorIs(t, err, context.Canceled)
}

// TestServiceRejectsNilStatus verifies an invalid successful response is reported.
func TestServiceRejectsNilStatus(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockFilteringService(t)
	service.EXPECT().FilteringStatus(mock.Anything).Return(nil, nil).Once()

	_, err := NewService(service).Status(t.Context())

	require.ErrorIs(t, err, errNilStatus)
}
