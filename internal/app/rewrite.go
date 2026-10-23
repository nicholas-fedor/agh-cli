// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

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
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - *RewriteManagement: management bound to the production service factory and
//     the production credential resolver.
func NewRewriteManagement(ctx context.Context) *RewriteManagement {
	return NewRewriteManagementWithResolver(NewCredentialResolver(ctx))
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
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
	selection Selection,
	successMessage string,
	operation rewriteMutationOperation,
) ([]RewriteMutationResult, error) {
	targets, err := selectTargets(ctx, selection, a.resolve)
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
	selection Selection,
	resolve instance.CredentialResolver,
	operation func(context.Context, execution.Target[instance.Config]) (T, error),
) ([]T, int, error) {
	targets, err := selectOrderedTargets(ctx, selection, resolve)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve rewrite read targets: %w", err)
	}

	results, count, err := runAcrossTargets(ctx, targets, "rewrite read", operation)
	if err != nil {
		return results, count, fmt.Errorf("run rewrite read: %w", err)
	}

	return results, count, nil
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
