// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

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

// runAcrossTargets executes one operation across resolved targets and collects results.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - targets: resolved instance targets in execution order.
//   - operationName: operation label used in the aggregate error messages.
//   - operation: per-target operation producing one result value.
//
// Returns:
//   - []T: one result per successful target in completion order.
//   - int: the number of targets.
//   - error: a wrapped execution or reporting error.
func runAcrossTargets[T any](
	ctx context.Context,
	targets []execution.Target[instance.Config],
	operationName string,
	operation func(context.Context, execution.Target[instance.Config]) (T, error),
) ([]T, int, error) {
	results := make([]T, 0, len(targets))
	report := execution.Run(
		ctx,
		targets,
		execution.AdaptOperation(
			func(ctx context.Context, target execution.Target[instance.Config]) error {
				result, operationErr := operation(ctx, target)
				if operationErr != nil {
					return fmt.Errorf("execute %s for %q: %w", operationName, target.Name, operationErr)
				}

				results = append(results, result)

				return nil
			},
		),
	)

	reportErr := report.Err()
	if reportErr != nil {
		return results, len(targets), fmt.Errorf("report %s outcomes: %w", operationName, reportErr)
	}

	return results, len(targets), nil
}

// runServiceMutation applies one domain mutation to every resolved target.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - targets: resolved instance targets in execution order.
//   - operationName: operation label used in the aggregate error messages.
//   - useCase: factory creating the domain service for one instance configuration.
//   - operation: domain mutation applied to each resolved instance service.
//   - success: builds the per-instance result value from the target name.
//
// Returns:
//   - []T: one result per successful target in completion order.
//   - error: a wrapped service or execution error.
func runServiceMutation[S, T any](
	ctx context.Context,
	targets []execution.Target[instance.Config],
	operationName string,
	useCase func(instance.Config) (S, error),
	operation func(context.Context, S) error,
	success func(string) T,
) ([]T, error) {
	results, _, err := runAcrossTargets(
		ctx,
		targets,
		operationName,
		func(ctx context.Context, target execution.Target[instance.Config]) (T, error) {
			service, useCaseErr := useCase(target.Value)
			if useCaseErr != nil {
				return success(target.Name), fmt.Errorf(
					"create %s use case for %q: %w",
					operationName,
					target.Name,
					useCaseErr,
				)
			}

			operationErr := operation(ctx, service)
			if operationErr != nil {
				return success(target.Name), fmt.Errorf("apply %s: %w", operationName, operationErr)
			}

			return success(target.Name), nil
		},
	)
	if err != nil {
		return results, fmt.Errorf("run %s: %w", operationName, err)
	}

	return results, nil
}
