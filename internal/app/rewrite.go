// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/connection"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

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
	feature[adguard.RewriteService, rewrite.Service]
}

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
	return wireRewriteManagement(
		func(cfg instance.Config) (adguard.RewriteService, error) {
			return connection.New(cfg)
		},
		resolve,
	)
}

// wireRewriteManagement creates rewrite-management wiring around a service factory.
//
// Parameters:
//   - newService: factory building the public service of one instance.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - *RewriteManagement: management bound to the factory and the resolver.
func wireRewriteManagement(
	newService func(instance.Config) (adguard.RewriteService, error),
	resolve instance.CredentialResolver,
) *RewriteManagement {
	return &RewriteManagement{
		newService: newService,
		wrap:       rewrite.NewService,
		resolve:    resolve,
		name:       "rewrite",
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
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *RewriteManagement) Add(
	ctx context.Context,
	selection Selection,
	request rewrite.RuleRequest,
) ([]MutationResult, error) {
	results, err := m.mutate(
		ctx,
		selection,
		fmt.Sprintf("Added rewrite rule %s -> %s", request.Domain, request.Answer),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.Add(ctx, request)
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
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *RewriteManagement) Delete(
	ctx context.Context,
	selection Selection,
	request rewrite.RuleRequest,
) ([]MutationResult, error) {
	results, err := m.mutate(
		ctx,
		selection,
		fmt.Sprintf("Deleted rewrite rule %s -> %s", request.Domain, request.Answer),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.Delete(ctx, request)
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
func (m *RewriteManagement) GetSettings(
	ctx context.Context,
	selection Selection,
) ([]RewriteSettingsResult, error) {
	targets, err := selectOrderedTargets(ctx, selection, m.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve rewrite read targets: %w", err)
	}

	results, err := runOnInstances(ctx, targets, m.useCase,
		func(ctx context.Context, service *rewrite.Service, name string) (RewriteSettingsResult, error) {
			settings, settingsErr := service.GetSettings(ctx)
			if settingsErr != nil {
				return RewriteSettingsResult{}, fmt.Errorf("get rewrite settings: %w", settingsErr)
			}

			return RewriteSettingsResult{
				Instance: name,
				Enabled:  settings.Enabled,
			}, nil
		},
	)
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
func (m *RewriteManagement) List(
	ctx context.Context,
	selection Selection,
) ([]RewriteListResult, error) {
	targets, err := selectOrderedTargets(ctx, selection, m.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve rewrite read targets: %w", err)
	}

	results, err := runOnInstances(ctx, targets, m.useCase,
		func(ctx context.Context, service *rewrite.Service, name string) (RewriteListResult, error) {
			rules, listErr := service.List(ctx)
			if listErr != nil {
				return RewriteListResult{}, fmt.Errorf("list rewrite rules: %w", listErr)
			}

			return RewriteListResult{
				Instance:      name,
				Rules:         shapeRewriteRules(rules),
				InstanceCount: len(targets),
			}, nil
		},
	)
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
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *RewriteManagement) Update(
	ctx context.Context,
	selection Selection,
	request rewrite.RuleRequest,
) ([]MutationResult, error) {
	results, err := m.mutate(
		ctx,
		selection,
		fmt.Sprintf("Updated rewrite rule %s -> %s", request.Domain, request.Answer),
		func(ctx context.Context, service *rewrite.Service) error {
			return service.Update(ctx, request)
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
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *RewriteManagement) UpdateSettings(
	ctx context.Context,
	selection Selection,
	enabled bool,
) ([]MutationResult, error) {
	results, err := m.mutate(
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
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *RewriteManagement) WildcardAdd(
	ctx context.Context,
	selection Selection,
	zone string,
) ([]MutationResult, error) {
	results, err := m.mutate(
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
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *RewriteManagement) WildcardDelete(
	ctx context.Context,
	selection Selection,
	zone string,
) ([]MutationResult, error) {
	results, err := m.mutate(
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
