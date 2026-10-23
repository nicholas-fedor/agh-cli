// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// feature is the wiring every feature management shares.
//
// A management embeds one feature and keeps only its own use cases. The feature
// builds the domain service of each selected instance and runs mutations across
// the selection. Public is the [adguard] service interface the feature calls,
// and Domain is the domain service type that wraps it.
type feature[Public, Domain any] struct {
	// newService builds the public AdGuard Home service of one instance.
	newService func(instance.Config) (Public, error)
	// wrap builds the domain service around a public service.
	wrap func(Public) *Domain
	// resolve serves the configured credential source of every catalog entry.
	// A nil resolver leaves the configured password untouched, which keeps a
	// legacy plaintext configuration working.
	resolve instance.CredentialResolver
	// name labels the feature in error context, such as "client".
	name string
}

// mutate applies one domain mutation to every selected instance, in selection
// order, and reports the instances it changed.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - successMessage: per-instance success text reported on success.
//   - mutation: domain mutation applied to each resolved instance service.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped resolution, service, or execution error.
func (f *feature[Public, Domain]) mutate(
	ctx context.Context,
	selection Selection,
	successMessage string,
	mutation func(context.Context, *Domain) error,
) ([]MutationResult, error) {
	targets, err := selectTargets(ctx, selection, f.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve %s targets: %w", f.name, err)
	}

	results, err := mutateInstances(ctx, targets, f.useCase, mutation,
		func(name string) MutationResult {
			return MutationResult{Instance: name, Message: successMessage}
		},
	)
	if err != nil {
		return results, fmt.Errorf("run %s mutation: %w", f.name, err)
	}

	return results, nil
}

// useCase creates the domain service for one instance configuration.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - *Domain: domain service wrapping the instance service.
//   - error: a wrapped service-construction error.
func (f *feature[Public, Domain]) useCase(cfg instance.Config) (*Domain, error) {
	service, err := f.newService(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure %s service: %w", f.name, err)
	}

	return f.wrap(service), nil
}
