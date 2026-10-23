// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/client"
	"github.com/nicholas-fedor/agh-cli/internal/connection"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// ClientListResult contains the successfully retrieved rows for one instance.
type ClientListResult struct {
	// Instance identifies the source instance.
	Instance string
	// Rows contains the retrieved clients in service order.
	Rows []client.Row
	// InstanceCount is the number of selected targets.
	InstanceCount int
}

// ClientManagement coordinates client use cases across selected instances.
type ClientManagement struct {
	feature[adguard.ClientsService, client.Service]
}

// NewClientManagement creates production client-management wiring.
//
// The management resolves every configured credential source, so a keyring,
// mounted-file, or environment instance is served without the command layer
// reading a secret.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - *ClientManagement: management bound to the production service factory and
//     the production credential resolver.
func NewClientManagement(ctx context.Context) *ClientManagement {
	return NewClientManagementWithResolver(NewCredentialResolver(ctx))
}

// NewClientManagementWithResolver creates client-management wiring that resolves
// instance credentials before a service is built.
//
// Parameters:
//   - resolve: resolver applied to every catalog entry.
//
// Returns:
//   - *ClientManagement: management bound to the production service factory and
//     the supplied resolver.
func NewClientManagementWithResolver(
	resolve instance.CredentialResolver,
) *ClientManagement {
	return wireClientManagement(
		func(cfg instance.Config) (adguard.ClientsService, error) {
			return connection.New(cfg)
		},
		resolve,
	)
}

// wireClientManagement creates client-management wiring around a service factory.
//
// Parameters:
//   - newService: factory building the public service of one instance.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - *ClientManagement: management bound to the factory and the resolver.
func wireClientManagement(
	newService func(instance.Config) (adguard.ClientsService, error),
	resolve instance.CredentialResolver,
) *ClientManagement {
	return &ClientManagement{
		newService: newService,
		wrap:       client.NewService,
		resolve:    resolve,
		name:       "client",
	}
}

// Add creates a client on every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - settings: client values sent to every selected instance.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *ClientManagement) Add(
	ctx context.Context,
	selection Selection,
	settings client.Settings,
) ([]MutationResult, error) {
	results, err := m.mutate(
		ctx,
		selection,
		"Added client "+settings.Name,
		func(ctx context.Context, service *client.Service) error {
			err := service.Add(ctx, settings)
			if err != nil {
				return fmt.Errorf("add client: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return results, fmt.Errorf("add client across instances: %w", err)
	}

	return results, nil
}

// Delete removes a client from every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - name: client name to remove.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *ClientManagement) Delete(
	ctx context.Context,
	selection Selection,
	name string,
) ([]MutationResult, error) {
	results, err := m.mutate(
		ctx,
		selection,
		"Deleted client "+name,
		func(ctx context.Context, service *client.Service) error {
			err := service.Delete(ctx, client.DeleteRequest{Name: name})
			if err != nil {
				return fmt.Errorf("delete client: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return results, fmt.Errorf("delete client across instances: %w", err)
	}

	return results, nil
}

// List retrieves clients from every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//
// Returns:
//   - []ClientListResult: retrieved rows in configuration order, even when some
//     instances failed.
//   - error: a wrapped service or execution error.
func (m *ClientManagement) List(
	ctx context.Context,
	selection Selection,
) ([]ClientListResult, error) {
	targets, err := selectOrderedTargets(ctx, selection, m.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve client targets: %w", err)
	}

	results, err := runOnInstances(ctx, targets, m.useCase,
		func(ctx context.Context, service *client.Service, name string) (ClientListResult, error) {
			result, listErr := service.List(ctx)
			if listErr != nil {
				return ClientListResult{}, fmt.Errorf("list clients: %w", listErr)
			}

			return ClientListResult{Instance: name, Rows: result.Rows, InstanceCount: len(targets)}, nil
		},
	)
	if err != nil {
		return results, fmt.Errorf("list clients across instances: %w", err)
	}

	return results, nil
}

// Update applies a client patch to every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - settings: client values sent to every selected instance.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (m *ClientManagement) Update(
	ctx context.Context,
	selection Selection,
	settings client.Settings,
) ([]MutationResult, error) {
	results, err := m.mutate(
		ctx,
		selection,
		"Updated client "+settings.Name,
		func(ctx context.Context, service *client.Service) error {
			err := service.Update(ctx, settings)
			if err != nil {
				return fmt.Errorf("update client: %w", err)
			}

			return nil
		},
	)
	if err != nil {
		return results, fmt.Errorf("update client across instances: %w", err)
	}

	return results, nil
}
