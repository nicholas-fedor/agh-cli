// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"time"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/filtering"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// FilteringSelection contains the instance-selection inputs for a filtering operation.
type FilteringSelection struct {
	// Instances contains the configured instance mappings.
	Instances instance.Source
	// Names contains explicit instance names in first-occurrence order.
	Names []string
	// ConfigPath identifies the configuration file used to order status results.
	ConfigPath string
	// All selects every configured instance when true.
	All bool
}

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
	// Index is the zero-based target position.
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

// filteringRequestTimeout is the per-request timeout for constructed AdGuard clients.
const filteringRequestTimeout = 10 * time.Second

// NewFilteringManagement creates production filtering-management wiring.
//
// The management resolves every configured credential source, so a keyring,
// mounted-file, or environment instance is served without the command layer
// reading a secret.
//
// Returns:
//   - *FilteringManagement: management bound to the production service factory
//     and the production credential resolver.
func NewFilteringManagement() *FilteringManagement {
	return NewFilteringManagementWithResolver(NewCredentialResolver())
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
	selection FilteringSelection,
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
	selection FilteringSelection,
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
	selection FilteringSelection,
) ([]FilteringStatusResult, error) {
	targets, err := filteringStatusTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve filtering status targets: %w", err)
	}

	results := make([]FilteringStatusResult, 0, len(targets))
	nextIndex := 0
	report := execution.Run(
		ctx,
		targets,
		execution.AdaptOperation(
			func(ctx context.Context, target execution.Target[instance.Config]) error {
				index := nextIndex
				nextIndex++

				service, useCaseErr := a.useCase(target.Value)
				if useCaseErr != nil {
					return fmt.Errorf("create filtering use case for %q: %w", target.Name, useCaseErr)
				}

				status, statusErr := service.Status(ctx)
				if statusErr != nil {
					return fmt.Errorf("get filtering status: %w", statusErr)
				}

				results = append(results, FilteringStatusResult{
					Filters:          shapeFilteringSubscriptions(status.Filters),
					WhitelistFilters: shapeFilteringSubscriptions(status.WhitelistFilters),
					Instance:         target.Name,
					Index:            index,
					InstanceCount:    len(targets),
				})

				return nil
			},
		),
	)

	reportErr := report.Err()
	if reportErr != nil {
		return results, fmt.Errorf("report filtering status outcomes: %w", reportErr)
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
	selection FilteringSelection,
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
	selection FilteringSelection,
	successMessage string,
	operation filteringMutationOperation,
) ([]FilteringMutationResult, error) {
	targets, err := filteringTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve filtering targets: %w", err)
	}

	results, err := runServiceMutation(
		ctx,
		targets,
		"filtering mutation",
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

// filteringSelectedConfigs applies filtering selection policy to the configured
// instances.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []instance.Config: selected configurations in selection order.
//   - error: a wrapped credential or selection error.
func filteringSelectedConfigs(
	ctx context.Context,
	selection FilteringSelection,
	resolve instance.CredentialResolver,
) ([]instance.Config, error) {
	catalog, err := instance.CatalogFromSourceResolved(ctx, selection.Instances, resolve)
	if err != nil {
		return nil, fmt.Errorf("create filtering catalog: %w", err)
	}

	mode := instance.ExplicitOrDefaultSelection
	if selection.All {
		mode = instance.AllSelection
	}

	selected, err := catalog.Select(selection.Names, mode)
	if err != nil {
		return nil, fmt.Errorf("select filtering instances: %w", err)
	}

	return selected, nil
}

// filteringStatusNames returns configured order with a deterministic sorted fallback.
//
// Parameters:
//   - configPath: path to the configuration file; an empty path sorts directly.
//   - selected: selected configurations keyed by instance name.
//
// Returns:
//   - []string: instance names in configuration-file order, or sorted by name when
//     the configuration order is unavailable.
func filteringStatusNames(configPath string, selected map[string]instance.Config) []string {
	if configPath == "" {
		return slices.Sorted(maps.Keys(selected))
	}

	manager, err := config.Load(configPath)
	if err != nil {
		return slices.Sorted(maps.Keys(selected))
	}

	return manager.OrderedNames()
}

// filteringStatusTargets resolves status targets in configuration-file order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []execution.Target[instance.Config]: resolved targets in configured order.
//   - error: a wrapped selection error.
func filteringStatusTargets(
	ctx context.Context,
	selection FilteringSelection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	selected, err := filteringSelectedConfigs(ctx, selection, resolve)
	if err != nil {
		return nil, fmt.Errorf("select filtering status targets: %w", err)
	}

	selectedByName := make(map[string]instance.Config, len(selected))
	for _, cfg := range selected {
		selectedByName[cfg.Name] = cfg
	}

	names := filteringStatusNames(selection.ConfigPath, selectedByName)
	configs := make([]instance.Config, 0, len(names))

	for _, name := range names {
		if cfg, ok := selectedByName[name]; ok {
			configs = append(configs, cfg)
		}
	}

	return filteringTargetsFromConfigs(configs), nil
}

// filteringTargets resolves mutation targets in selection order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []execution.Target[instance.Config]: resolved targets in selection order.
//   - error: a wrapped selection error.
func filteringTargets(
	ctx context.Context,
	selection FilteringSelection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	selected, err := filteringSelectedConfigs(ctx, selection, resolve)
	if err != nil {
		return nil, fmt.Errorf("select filtering targets: %w", err)
	}

	return filteringTargetsFromConfigs(selected), nil
}

// filteringTargetsFromConfigs wraps resolved configurations as execution targets.
//
// Parameters:
//   - configs: resolved instance configurations in target order.
//
// Returns:
//   - []execution.Target[instance.Config]: targets wrapping each configuration.
func filteringTargetsFromConfigs(configs []instance.Config) []execution.Target[instance.Config] {
	targets := make([]execution.Target[instance.Config], 0, len(configs))
	for _, cfg := range configs {
		targets = append(targets, execution.Target[instance.Config]{
			Name:  cfg.Name,
			Value: cfg,
		})
	}

	return targets
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
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}

	baseURL := (&url.URL{Scheme: scheme, Host: cfg.Host}).String()
	options := []adguard.Option{adguard.WithRequestTimeout(filteringRequestTimeout)}
	if cfg.Username != "" || cfg.Password != "" {
		options = append(options, adguard.WithBasicAuth(cfg.Username, cfg.Password))
	}

	service, err := adguard.NewClient(baseURL, options...)
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
