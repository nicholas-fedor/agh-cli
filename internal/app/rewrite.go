// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// RewriteSelection contains the instance-selection inputs for a rewrite operation.
type RewriteSelection struct {
	// Instances contains the configured instance mappings.
	Instances instance.Source
	// Names contains explicit instance names in first-occurrence order.
	Names []string
	// ConfigPath identifies the configuration file used to order list results.
	ConfigPath string
	// All selects every configured instance when true.
	All bool
}

// RewriteRuleInput contains command values for one rewrite-rule mutation.
type RewriteRuleInput struct {
	// Domain is the rewritten domain.
	Domain string
	// Answer is the rewritten answer.
	Answer string
	// Enabled controls whether the rule is active.
	Enabled bool
}

// RewriteRule contains display values for one rewrite rule.
type RewriteRule struct {
	// Domain is the rewritten domain or an empty string when absent.
	Domain string
	// Answer is the rewritten answer or an empty string when absent.
	Answer string
	// Enabled reports whether the rule is explicitly enabled.
	Enabled bool
}

// RewriteManagement coordinates rewrite use cases across selected instances.
type RewriteManagement struct {
	newService rewriteServiceFactory
	// resolve serves the configured credential source of every catalog entry.
	// A nil resolver leaves the configured password untouched, which keeps a
	// legacy plaintext configuration working.
	resolve instance.CredentialResolver
}

// rewriteServiceFactory creates one public rewrite service per instance.
type rewriteServiceFactory func(instance.Config) (adguard.RewriteService, error)

// rewriteMutationOperation applies one domain mutation to an instance service.
type rewriteMutationOperation func(context.Context, *rewrite.Service) error

// NewRewriteManagement creates production rewrite-management wiring.
//
// The management resolves every configured credential source, so a keyring,
// mounted-file, or environment instance is served without the command layer
// reading a secret.
//
// Returns:
//   - *RewriteManagement: management bound to the production service factory and
//     the production credential resolver.
func NewRewriteManagement() *RewriteManagement {
	return NewRewriteManagementWithResolver(NewCredentialResolver())
}

// NewRewriteManagementWithResolver creates rewrite-management wiring that
// resolves instance credentials before a service is built.
//
// Parameters:
//   - resolve: resolver applied to every catalog entry.
//
// Returns:
//   - *RewriteManagement: management bound to the production service factory and
//     the supplied resolver.
func NewRewriteManagementWithResolver(
	resolve instance.CredentialResolver,
) *RewriteManagement {
	return &RewriteManagement{
		newService: newAdguardRewriteService,
		resolve:    resolve,
	}
}

// Add creates one rewrite rule on every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - request: rewrite values sent to every selected instance.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *RewriteManagement) Add(
	ctx context.Context,
	selection RewriteSelection,
	request RewriteRuleInput,
) ([]RewriteMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		fmt.Sprintf("Added rewrite rule %s -> %s", request.Domain, request.Answer),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.Add(ctx, rewrite.RuleRequest{
				Domain:  request.Domain,
				Answer:  request.Answer,
				Enabled: request.Enabled,
			})
		},
	)
	if err != nil {
		return results, fmt.Errorf("add rewrite across instances: %w", err)
	}

	return results, nil
}

// Delete removes one rewrite rule from every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - request: rewrite values identifying the rule to remove.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *RewriteManagement) Delete(
	ctx context.Context,
	selection RewriteSelection,
	request RewriteRuleInput,
) ([]RewriteMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		fmt.Sprintf("Deleted rewrite rule %s -> %s", request.Domain, request.Answer),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.Delete(ctx, rewrite.RuleRequest{
				Domain:  request.Domain,
				Answer:  request.Answer,
				Enabled: request.Enabled,
			})
		},
	)
	if err != nil {
		return results, fmt.Errorf("delete rewrite across instances: %w", err)
	}

	return results, nil
}

// GetSettings retrieves global rewrite settings in configuration order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//
// Returns:
//   - []RewriteSettingsResult: retrieved settings in configuration order.
//   - error: a wrapped resolution, service, or execution error.
func (a *RewriteManagement) GetSettings(
	ctx context.Context,
	selection RewriteSelection,
) ([]RewriteSettingsResult, error) {
	nextIndex := 0

	results, instanceCount, err := runRewriteReadOperation(
		ctx,
		selection,
		a.resolve,
		func(ctx context.Context, target execution.Target[instance.Config]) (RewriteSettingsResult, error) {
			index := nextIndex
			nextIndex++

			service, useCaseErr := a.useCase(target.Value)
			if useCaseErr != nil {
				return RewriteSettingsResult{}, fmt.Errorf(
					"create rewrite use case for %q: %w",
					target.Name,
					useCaseErr,
				)
			}

			settings, settingsErr := service.GetSettings(ctx)
			if settingsErr != nil {
				return RewriteSettingsResult{}, fmt.Errorf("get rewrite settings: %w", settingsErr)
			}

			return RewriteSettingsResult{
				Instance: target.Name,
				Enabled:  settings.Enabled,
				Index:    index,
			}, nil
		},
	)
	for index := range results {
		results[index].InstanceCount = instanceCount
	}

	if err != nil {
		return results, fmt.Errorf("get rewrite settings across instances: %w", err)
	}

	return results, nil
}

// List retrieves rewrite rules from selected instances in configuration order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//
// Returns:
//   - []RewriteListResult: retrieved rules in configuration order.
//   - error: a wrapped resolution, service, or execution error.
func (a *RewriteManagement) List(
	ctx context.Context,
	selection RewriteSelection,
) ([]RewriteListResult, error) {
	nextIndex := 0

	results, instanceCount, err := runRewriteReadOperation(
		ctx,
		selection,
		a.resolve,
		func(ctx context.Context, target execution.Target[instance.Config]) (RewriteListResult, error) {
			index := nextIndex
			nextIndex++

			service, useCaseErr := a.useCase(target.Value)
			if useCaseErr != nil {
				return RewriteListResult{}, fmt.Errorf(
					"create rewrite use case for %q: %w",
					target.Name,
					useCaseErr,
				)
			}

			rules, listErr := service.List(ctx)
			if listErr != nil {
				return RewriteListResult{}, fmt.Errorf("list rewrite rules: %w", listErr)
			}

			return RewriteListResult{
				Instance: target.Name,
				Rules:    shapeRewriteRules(rules),
				Index:    index,
			}, nil
		},
	)
	for index := range results {
		results[index].InstanceCount = instanceCount
	}

	if err != nil {
		return results, fmt.Errorf("list rewrite rules across instances: %w", err)
	}

	return results, nil
}

// Update replaces one rewrite rule on every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - request: rewrite values sent to every selected instance.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *RewriteManagement) Update(
	ctx context.Context,
	selection RewriteSelection,
	request RewriteRuleInput,
) ([]RewriteMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		fmt.Sprintf("Updated rewrite rule %s -> %s", request.Domain, request.Answer),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.Update(ctx, rewrite.RuleRequest{
				Domain:  request.Domain,
				Answer:  request.Answer,
				Enabled: request.Enabled,
			})
		},
	)
	if err != nil {
		return results, fmt.Errorf("update rewrite across instances: %w", err)
	}

	return results, nil
}

// UpdateSettings applies global rewrite settings to every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - enabled: enables or disables DNS rewrites.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *RewriteManagement) UpdateSettings(
	ctx context.Context,
	selection RewriteSelection,
	enabled bool,
) ([]RewriteMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		fmt.Sprintf("Rewrite settings updated: enabled=%v", enabled),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.UpdateSettings(ctx, rewrite.Settings{Enabled: enabled})
		},
	)
	if err != nil {
		return results, fmt.Errorf("update rewrite settings across instances: %w", err)
	}

	return results, nil
}

// WildcardAdd creates wildcard rules on every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - zone: DNS zone covered by the wildcard rules.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *RewriteManagement) WildcardAdd(
	ctx context.Context,
	selection RewriteSelection,
	zone string,
) ([]RewriteMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		"Added wildcard rewrite rules for "+zone,
		func(ctx context.Context, service *rewrite.Service) error {
			return service.WildcardAdd(ctx, zone)
		},
	)
	if err != nil {
		return results, fmt.Errorf("add wildcard rewrite rules across instances: %w", err)
	}

	return results, nil
}

// WildcardDelete removes wildcard rules from every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - zone: DNS zone whose bare and wildcard rules are removed.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *RewriteManagement) WildcardDelete(
	ctx context.Context,
	selection RewriteSelection,
	zone string,
) ([]RewriteMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		"Removed wildcard rewrite rules for "+zone,
		func(ctx context.Context, service *rewrite.Service) error {
			return service.WildcardDelete(ctx, zone)
		},
	)
	if err != nil {
		return results, fmt.Errorf("remove wildcard rewrite rules across instances: %w", err)
	}

	return results, nil
}

// runMutation executes one mutation across targets in selection order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - successMessage: per-instance success text reported on success.
//   - operation: domain mutation applied to each resolved instance service.
//
// Returns:
//   - []RewriteMutationResult: one success message per successful instance.
//   - error: a wrapped resolution, service, or execution error.
func (a *RewriteManagement) runMutation(
	ctx context.Context,
	selection RewriteSelection,
	successMessage string,
	operation rewriteMutationOperation,
) ([]RewriteMutationResult, error) {
	targets, err := rewriteTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve rewrite targets: %w", err)
	}

	results, err := runServiceMutation(
		ctx,
		targets,
		"rewrite mutation",
		a.useCase,
		operation,
		func(name string) RewriteMutationResult {
			return RewriteMutationResult{Instance: name, Message: successMessage}
		},
	)
	if err != nil {
		return results, fmt.Errorf("run rewrite mutation: %w", err)
	}

	return results, nil
}

// useCase creates the domain service for one instance configuration.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - *domainrewrite.Service: domain service wrapping the instance service.
//   - error: a wrapped service-construction error.
func (a *RewriteManagement) useCase(cfg instance.Config) (*rewrite.Service, error) {
	service, err := a.newService(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure rewrite service: %w", err)
	}

	return rewrite.NewService(service), nil
}

// runRewriteReadOperation executes one read operation in configuration order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - operation: per-instance operation producing one result value.
//
// Returns:
//   - []T: one result per successful instance in configured order.
//   - int: the number of selected instances.
//   - error: a wrapped resolution or execution error.
func runRewriteReadOperation[T any](
	ctx context.Context,
	selection RewriteSelection,
	resolve instance.CredentialResolver,
	operation func(context.Context, execution.Target[instance.Config]) (T, error),
) ([]T, int, error) {
	targets, err := rewriteOrderedTargets(ctx, selection, resolve)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve rewrite read targets: %w", err)
	}

	results, count, err := runAcrossTargets(ctx, targets, "rewrite read", operation)
	if err != nil {
		return results, count, fmt.Errorf("run rewrite read: %w", err)
	}

	return results, count, nil
}

// rewriteTargets resolves mutation targets in selection order.
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
func rewriteTargets(
	ctx context.Context,
	selection RewriteSelection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	selected, err := rewriteSelectedConfigs(ctx, selection, resolve)
	if err != nil {
		return nil, fmt.Errorf("select rewrite targets: %w", err)
	}

	return rewriteTargetsFromConfigs(selected), nil
}

// rewriteOrderedTargets resolves read targets in configuration-file order.
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
func rewriteOrderedTargets(
	ctx context.Context,
	selection RewriteSelection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	selected, err := rewriteSelectedConfigs(ctx, selection, resolve)
	if err != nil {
		return nil, fmt.Errorf("select rewrite read targets: %w", err)
	}

	selectedByName := make(map[string]instance.Config, len(selected))
	for _, cfg := range selected {
		selectedByName[cfg.Name] = cfg
	}

	names := rewriteConfiguredNames(selection.ConfigPath, selectedByName)
	configs := make([]instance.Config, 0, len(names))

	for _, name := range names {
		if cfg, exists := selectedByName[name]; exists {
			configs = append(configs, cfg)
		}
	}

	return rewriteTargetsFromConfigs(configs), nil
}

// rewriteSelectedConfigs applies selection policy to the configured instances.
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
func rewriteSelectedConfigs(
	ctx context.Context,
	selection RewriteSelection,
	resolve instance.CredentialResolver,
) ([]instance.Config, error) {
	catalog, err := instance.CatalogFromSourceResolved(ctx, selection.Instances, resolve)
	if err != nil {
		return nil, fmt.Errorf("create rewrite catalog: %w", err)
	}

	mode := instance.ExplicitOrDefaultSelection
	if selection.All {
		mode = instance.AllSelection
	}

	selected, err := catalog.Select(selection.Names, mode)
	if err != nil {
		return nil, fmt.Errorf("select rewrite instances: %w", err)
	}

	return selected, nil
}

// rewriteConfiguredNames returns configured order with a sorted fallback.
//
// Parameters:
//   - configPath: path to the configuration file; an empty path sorts directly.
//   - selected: selected configurations keyed by instance name.
//
// Returns:
//   - []string: instance names in configuration-file order, or sorted by name when
//     the configuration order is unavailable.
func rewriteConfiguredNames(
	configPath string,
	selected map[string]instance.Config,
) []string {
	if configPath == "" {
		return slices.Sorted(maps.Keys(selected))
	}

	manager, err := config.Load(configPath)
	if err != nil {
		return slices.Sorted(maps.Keys(selected))
	}

	return manager.OrderedNames()
}

// rewriteTargetsFromConfigs wraps configurations as execution targets.
//
// Parameters:
//   - configs: resolved instance configurations in target order.
//
// Returns:
//   - []execution.Target[instance.Config]: targets wrapping each configuration.
func rewriteTargetsFromConfigs(configs []instance.Config) []execution.Target[instance.Config] {
	targets := make([]execution.Target[instance.Config], 0, len(configs))
	for _, cfg := range configs {
		targets = append(targets, execution.Target[instance.Config]{Name: cfg.Name, Value: cfg})
	}

	return targets
}

// newAdguardRewriteService creates the production rewrite service factory.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - adguard.RewriteService: the configured public rewrite service.
//   - error: a wrapped client-construction error.
//
//nolint:ireturn // The factory intentionally depends on the public service interface.
func newAdguardRewriteService(cfg instance.Config) (adguard.RewriteService, error) {
	client, err := newAdguardClientsServiceWithHTTPClient(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("build rewrite service: %w", err)
	}

	return client, nil
}
