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

// FilteringMutationResult contains the success message for one instance.
type FilteringMutationResult struct {
	// Instance identifies the successful target.
	Instance string
	// Message is the operation-specific success text.
	Message string
}

// FilteringSubscription contains one display-ready filtering subscription.
type FilteringSubscription struct {
	// Name is the subscription display name.
	Name string
	// URL is the subscription location.
	URL string
	// Enabled reports whether the subscription is enabled.
	Enabled bool
	// RulesCount is the number of rules in the subscription.
	RulesCount uint32
}

// FilteringStatusResult contains one successfully retrieved filtering status.
type FilteringStatusResult struct {
	// Filters contains the filtering subscriptions when the service reports them.
	Filters *[]FilteringSubscription
	// WhitelistFilters contains the allowlist subscriptions when the service
	// reports them.
	WhitelistFilters *[]FilteringSubscription
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
	newService filteringServiceFactory
	// resolve serves the configured credential source of every catalog entry.
	// A nil resolver leaves the configured password untouched, which keeps a
	// legacy plaintext configuration working.
	resolve instance.CredentialResolver
}

// filteringServiceFactory builds one public filtering service per instance.
type filteringServiceFactory func(instance.Config) (adguard.FilteringService, error)

// filteringMutationOperation applies one domain mutation to a resolved instance.
type filteringMutationOperation func(context.Context, *filtering.Service) error

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
	return &FilteringManagement{
		newService: newAdguardFilteringService,
		resolve:    resolve,
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
//   - []FilteringMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *FilteringManagement) AddURL(
	ctx context.Context,
	selection Selection,
	name string,
	location string,
	whitelist bool,
) ([]FilteringMutationResult, error) {
	request := filtering.URLRequest{
		Name:      name,
		URL:       location,
		Whitelist: whitelist,
	}
	results, err := a.runMutation(
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
//   - []FilteringMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *FilteringManagement) RemoveURL(
	ctx context.Context,
	selection Selection,
	location string,
) ([]FilteringMutationResult, error) {
	request := filtering.URLRequest{
		Name:      "",
		URL:       location,
		Whitelist: false,
	}
	results, err := a.runMutation(
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
func (a *FilteringManagement) Status(
	ctx context.Context,
	selection Selection,
) ([]FilteringStatusResult, error) {
	targets, err := selectOrderedTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve filtering status targets: %w", err)
	}

	results, err := runOnInstances(ctx, targets, a.useCase,
		func(ctx context.Context, service *filtering.Service, name string) (FilteringStatusResult, error) {
			status, statusErr := service.Status(ctx)
			if statusErr != nil {
				return FilteringStatusResult{}, fmt.Errorf("get filtering status: %w", statusErr)
			}

			return FilteringStatusResult{
				Filters:          shapeFilteringSubscriptions(status.Filters),
				WhitelistFilters: shapeFilteringSubscriptions(status.WhitelistFilters),
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
//   - []FilteringMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *FilteringManagement) UpdateConfig(
	ctx context.Context,
	selection Selection,
	enabled bool,
	interval int64,
) ([]FilteringMutationResult, error) {
	request := filtering.ConfigRequest{
		Enabled:  enabled,
		Interval: interval,
	}
	results, err := a.runMutation(
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

// runMutation coordinates one domain mutation across selected instances.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - successMessage: per-instance success text reported on success.
//   - operation: domain mutation applied to each resolved instance service.
//
// Returns:
//   - []FilteringMutationResult: one success message per successful instance.
//   - error: a wrapped resolution, service, or execution error.
func (a *FilteringManagement) runMutation(
	ctx context.Context,
	selection Selection,
	successMessage string,
	operation filteringMutationOperation,
) ([]FilteringMutationResult, error) {
	targets, err := selectTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve filtering targets: %w", err)
	}

	results, err := mutateInstances(
		ctx,
		targets,
		a.useCase,
		operation,
		func(name string) FilteringMutationResult {
			return FilteringMutationResult{Instance: name, Message: successMessage}
		},
	)
	if err != nil {
		return results, fmt.Errorf("run filtering mutation: %w", err)
	}

	return results, nil
}

// useCase creates the domain service for one instance configuration.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - *domainfiltering.Service: domain service wrapping the instance service.
//   - error: a wrapped service-construction error.
func (a *FilteringManagement) useCase(cfg instance.Config) (*filtering.Service, error) {
	service, err := a.newService(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure filtering service: %w", err)
	}

	return filtering.NewService(service), nil
}

// newAdguardFilteringService creates the production filtering service factory.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - adguard.FilteringService: the configured public filtering service.
//   - error: a wrapped client-construction error.
//
//nolint:ireturn // The factory intentionally depends on the public service interface.
func newAdguardFilteringService(cfg instance.Config) (adguard.FilteringService, error) {
	service, err := connection.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("build filtering service: %w", err)
	}

	return service, nil
}

// shapeFilteringSubscriptions converts domain subscriptions into display results.
//
// Parameters:
//   - subscriptions: domain subscriptions; nil stays nil.
//
// Returns:
//   - *[]FilteringSubscription: display subscriptions, or nil for absent input.
func shapeFilteringSubscriptions(
	subscriptions *[]filtering.Subscription,
) *[]FilteringSubscription {
	if subscriptions == nil {
		return nil
	}

	shaped := make([]FilteringSubscription, 0, len(*subscriptions))
	for _, subscription := range *subscriptions {
		shaped = append(shaped, FilteringSubscription{
			Name:       subscription.Name,
			Enabled:    subscription.Enabled,
			RulesCount: subscription.RulesCount,
			URL:        subscription.URL,
		})
	}

	return &shaped
}
