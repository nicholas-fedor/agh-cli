// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// MutationResult reports one instance a mutation changed.
type MutationResult struct {
	// Instance identifies the changed instance.
	Instance string
	// Message is the operation-specific success text.
	Message string
}

// selectTargets selects configured instances as execution targets in selection
// order.
//
// Parameters:
//   - ctx: context carrying the configuration of the run and governing
//     credential resolution.
//   - selection: the instances the operator selected.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []execution.Target[instance.Config]: resolved targets in selection order.
//   - error: a wrapped selection error.
func selectTargets(
	ctx context.Context,
	selection Selection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	selected, err := selectInstances(ctx, selection, resolve)
	if err != nil {
		return nil, fmt.Errorf("select targets: %w", err)
	}

	return instanceTargets(selected), nil
}

// selectOrderedTargets selects configured instances as execution targets in
// configuration-file order.
//
// Parameters:
//   - ctx: context carrying the configuration of the run and governing
//     credential resolution.
//   - selection: the instances the operator selected.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []execution.Target[instance.Config]: resolved targets in configured order.
//   - error: a wrapped selection error.
func selectOrderedTargets(
	ctx context.Context,
	selection Selection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	selected, err := selectInstances(ctx, selection, resolve)
	if err != nil {
		return nil, fmt.Errorf("select targets: %w", err)
	}

	selectedByName := make(map[string]instance.Config, len(selected))
	for _, cfg := range selected {
		selectedByName[cfg.Name] = cfg
	}

	ordered := make([]instance.Config, 0, len(selected))

	for _, name := range configuredOrder(ctx) {
		if cfg, ok := selectedByName[name]; ok {
			ordered = append(ordered, cfg)
		}
	}

	return instanceTargets(ordered), nil
}

// instanceTargets wraps instance configurations as execution targets.
//
// Parameters:
//   - configs: resolved instance configurations in target order.
//
// Returns:
//   - []execution.Target[instance.Config]: targets wrapping each configuration.
func instanceTargets(configs []instance.Config) []execution.Target[instance.Config] {
	targets := make([]execution.Target[instance.Config], 0, len(configs))
	for _, cfg := range configs {
		targets = append(targets, execution.Target[instance.Config]{Name: cfg.Name, Value: cfg})
	}

	return targets
}

// runOnInstances runs operation against the domain service of every target, in
// target order, and gathers the result of each target that succeeded.
//
// A target whose service cannot be configured fails like any other, so the
// remaining targets still run.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - targets: resolved instance targets in execution order.
//   - useCase: factory creating the domain service for one instance
//     configuration.
//   - operation: per-target operation producing one result from the target's
//     service and name.
//
// Returns:
//   - []Result: the results of the targets that succeeded, in execution order, even
//     when some targets failed.
//   - error: a wrapped [execution.AggregateError] naming every failed target.
func runOnInstances[Service, Result any](
	ctx context.Context,
	targets []execution.Target[instance.Config],
	useCase func(instance.Config) (Service, error),
	operation func(ctx context.Context, service Service, name string) (Result, error),
) ([]Result, error) {
	results, err := execution.Collect(ctx, targets,
		func(ctx context.Context, target execution.Target[instance.Config]) (Result, error) {
			service, useCaseErr := useCase(target.Value)
			if useCaseErr != nil {
				var zero Result

				return zero, fmt.Errorf("configure service: %w", useCaseErr)
			}

			return operation(ctx, service, target.Name)
		},
	)
	if err != nil {
		return results, fmt.Errorf("run on instances: %w", err)
	}

	return results, nil
}

// mutateInstances applies one domain mutation to every target and reports the
// targets it changed.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - targets: resolved instance targets in execution order.
//   - useCase: factory creating the domain service for one instance
//     configuration.
//   - mutation: domain mutation applied to each target's service.
//   - success: builds the result of one changed target from its name.
//
// Returns:
//   - []Result: one result per changed target, in execution order, even when some
//     targets failed.
//   - error: a wrapped [execution.AggregateError] naming every failed target.
func mutateInstances[Service, Result any](
	ctx context.Context,
	targets []execution.Target[instance.Config],
	useCase func(instance.Config) (Service, error),
	mutation func(ctx context.Context, service Service) error,
	success func(name string) Result,
) ([]Result, error) {
	results, err := runOnInstances(ctx, targets, useCase,
		func(ctx context.Context, service Service, name string) (Result, error) {
			mutationErr := mutation(ctx, service)
			if mutationErr != nil {
				var zero Result

				return zero, fmt.Errorf("apply mutation: %w", mutationErr)
			}

			return success(name), nil
		},
	)
	if err != nil {
		return results, fmt.Errorf("mutate instances: %w", err)
	}

	return results, nil
}
