// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/connection"
	"github.com/nicholas-fedor/agh-cli/internal/filtering"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// FilteringStatusResult contains one successfully retrieved filtering status.
type FilteringStatusResult struct {
	// Filters contains the filtering subscriptions when the service reports them.
	Filters *[]filtering.Subscription
	// WhitelistFilters contains the allowlist subscriptions when the service
	// reports them.
	WhitelistFilters *[]filtering.Subscription
	// Instance identifies the source instance.
	Instance string
	// Index is the zero-based position of the result among the results of the
	// run.
	Index int
	// InstanceCount is the number of selected targets.
	InstanceCount int
}

// FilteringManagement coordinates filtering use cases across selected instances.
type FilteringManagement struct {
	feature[adguard.FilteringService, filtering.Service]
}

// NewFilteringManagement creates production filtering-management wiring.
//
// The management resolves every configured credential source, so a keyring,
// mounted-file, or environment instance is served without the command layer
// reading a secret.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - *FilteringManagement: management bound to the production service factory
//     and the production credential resolver.
func NewFilteringManagement(ctx context.Context) *FilteringManagement {
	return NewFilteringManagementWithResolver(NewCredentialResolver(ctx))
}

// NewFilteringManagementWithResolver creates filtering-management wiring that
// resolves instance credentials before a service is built.
//
// Parameters:
//   - resolve: resolver applied to every catalog entry.
//
// Returns:
//   - *FilteringManagement: management bound to the production service factory
//     and the supplied resolver.
func NewFilteringManagementWithResolver(
	resolve instance.CredentialResolver,
) *FilteringManagement {
	return wireFilteringManagement(
		func(cfg instance.Config) (adguard.FilteringService, error) {
			return connection.New(cfg)
		},
		resolve,
	)
}

// wireFilteringManagement creates filtering-management wiring around a service factory.
//
// Parameters:
//   - newService: factory building the public service of one instance.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - *FilteringManagement: management bound to the factory and the resolver.
func wireFilteringManagement(
	newService func(instance.Config) (adguard.FilteringService, error),
	resolve instance.CredentialResolver,
) *FilteringManagement {
	return &FilteringManagement{
		newService: newService,
		wrap:       filtering.NewService,
		resolve:    resolve,
		name:       "filtering",
	}
}

// AddURL adds a filtering subscription to every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - name: subscription display name.
//   - location: subscription location.
//   - whitelist: selects allowlist mode.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *FilteringManagement) AddURL(
	ctx context.Context,
	selection Selection,
	name string,
	location string,
	whitelist bool,
) ([]MutationResult, error) {
	request := filtering.URLRequest{
		Name:      name,
		URL:       location,
		Whitelist: whitelist,
	}
	results, err := m.mutate(
		ctx,
		selection,
		"Added filter URL "+name,
		func(ctx context.Context, service *filtering.Service) error {
			return service.AddURL(ctx, request)
		},
	)
	if err != nil {
		return results, fmt.Errorf("add filtering URL: %w", err)
	}

	return results, nil
}

// RemoveURL removes a filtering subscription from every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - location: subscription location to remove.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *FilteringManagement) RemoveURL(
	ctx context.Context,
	selection Selection,
	location string,
) ([]MutationResult, error) {
	request := filtering.URLRequest{
		Name:      "",
		URL:       location,
		Whitelist: false,
	}
	results, err := m.mutate(
		ctx,
		selection,
		"Removed filter URL "+location,
		func(ctx context.Context, service *filtering.Service) error {
			return service.RemoveURL(ctx, request)
		},
	)
	if err != nil {
		return results, fmt.Errorf("remove filtering URL: %w", err)
	}

	return results, nil
}

// Status retrieves filtering status from every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//
// Returns:
//   - []FilteringStatusResult: retrieved statuses in configuration order.
//   - error: a wrapped resolution, service, or execution error.
func (m *FilteringManagement) Status(
	ctx context.Context,
	selection Selection,
) ([]FilteringStatusResult, error) {
	targets, err := selectOrderedTargets(ctx, selection, m.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve filtering status targets: %w", err)
	}

	results, err := runOnInstances(ctx, targets, m.useCase,
		func(ctx context.Context, service *filtering.Service, name string) (FilteringStatusResult, error) {
			status, statusErr := service.Status(ctx)
			if statusErr != nil {
				return FilteringStatusResult{}, fmt.Errorf("get filtering status: %w", statusErr)
			}

			return FilteringStatusResult{
				Filters:          status.Filters,
				WhitelistFilters: status.WhitelistFilters,
				Instance:         name,
				Index:            0,
				InstanceCount:    len(targets),
			}, nil
		},
	)

	for index := range results {
		results[index].Index = index
	}

	if err != nil {
		return results, fmt.Errorf("report filtering status outcomes: %w", err)
	}

	return results, nil
}

// UpdateConfig applies filtering configuration to every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - enabled: enables or disables filtering.
//   - interval: automatic filter refresh interval in hours.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *FilteringManagement) UpdateConfig(
	ctx context.Context,
	selection Selection,
	enabled bool,
	interval int64,
) ([]MutationResult, error) {
	request := filtering.ConfigRequest{
		Enabled:  enabled,
		Interval: interval,
	}
	results, err := m.mutate(
		ctx,
		selection,
		fmt.Sprintf(
			"Filtering config updated: enabled=%v, interval=%d",
			enabled,
			interval,
		),
		func(ctx context.Context, service *filtering.Service) error {
			return service.UpdateConfig(ctx, request)
		},
	)
	if err != nil {
		return results, fmt.Errorf("update filtering config: %w", err)
	}

	return results, nil
}
