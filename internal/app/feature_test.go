// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/client"
	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

// errFeatureFactory is the failure returned by the test service factory.
var errFeatureFactory = errors.New("factory failed")

// TestFeatureUseCaseNamesFeatureOnFactoryFailure verifies that a factory failure
// keeps its cause and names the feature.
func TestFeatureUseCaseNamesFeatureOnFactoryFailure(t *testing.T) {
	t.Parallel()

	management := wireClientManagement(func(instance.Config) (adguard.ClientsService, error) {
		return nil, errFeatureFactory
	}, nil)

	service, err := management.useCase(instance.Config{
		Name:       goodInstance,
		Host:       testGoodHost,
		Scheme:     "",
		Username:   "",
		Password:   "",
		Credential: nil,
	})

	require.ErrorIs(t, err, errFeatureFactory)
	assert.Nil(t, service)
	assert.Contains(t, err.Error(), "configure client service")
}

// TestFeatureMutateReportsChangedInstances verifies that a mutation reports
// every instance it changed, keeps running after a failed instance, and names
// the feature and the failed instance in the error.
func TestFeatureMutateReportsChangedInstances(t *testing.T) {
	t.Parallel()

	management := wireClientManagement(func(cfg instance.Config) (adguard.ClientsService, error) {
		if cfg.Name == badInstance {
			return nil, errFeatureFactory
		}

		return mockAdguard.NewMockClientsService(t), nil
	}, nil)

	results, err := management.mutate(
		testInstancesContext(t),
		Selection{Names: []string{badInstance, goodInstance}},
		"changed",
		func(context.Context, *client.Service) error { return nil },
	)

	require.ErrorIs(t, err, errFeatureFactory)
	assert.Equal(t, []MutationResult{{Instance: goodInstance, Message: "changed"}}, results)
	assert.Contains(t, err.Error(), "run client mutation")

	aggregate, isAggregate := errors.AsType[execution.AggregateError[instance.Config]](err)
	require.True(t, isAggregate)
	require.Len(t, aggregate, 1)
	assert.Equal(t, badInstance, aggregate[0].Target.Name)
}

// TestFeatureMutateNamesFeatureOnSelectionFailure verifies that an unknown
// instance fails before any service is built and names the feature.
func TestFeatureMutateNamesFeatureOnSelectionFailure(t *testing.T) {
	t.Parallel()

	management := wireClientManagement(func(instance.Config) (adguard.ClientsService, error) {
		require.FailNow(t, "the service factory must not run")

		return nil, errFeatureFactory
	}, nil)

	results, err := management.mutate(
		testInstancesContext(t),
		Selection{Names: []string{"missing"}},
		"changed",
		func(context.Context, *client.Service) error { return nil },
	)

	require.Error(t, err)
	assert.Empty(t, results)
	assert.Contains(t, err.Error(), "resolve client targets")
}
