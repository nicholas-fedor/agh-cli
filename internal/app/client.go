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
	// Index is the zero-based position of the result among the results of the
	// run.
	Index int
	// InstanceCount is the number of selected targets.
	InstanceCount int
}

// clientServiceFactory creates a client-management service for one instance.
type clientServiceFactory func(instance.Config) (adguard.ClientsService, error)

// clientMutationOperation executes one mutation against an instance service.
type clientMutationOperation func(context.Context, *client.Service) error

// ClientManagement coordinates client use cases across selected instances.
type ClientManagement struct {
	newService clientServiceFactory
	// resolve serves the configured credential source of every catalog entry.
	// A nil resolver leaves the configured password untouched, which keeps a
	// legacy plaintext configuration working.
	resolve instance.CredentialResolver
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
	return &ClientManagement{
		newService: newAdguardClientsService,
		resolve:    resolve,
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
func (a *ClientManagement) Add(
	ctx context.Context,
	selection Selection,
	settings client.Settings,
) ([]MutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		"add client",
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
func (a *ClientManagement) Delete(
	ctx context.Context,
	selection Selection,
	name string,
) ([]MutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		"delete client",
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
func (a *ClientManagement) List(
	ctx context.Context,
	selection Selection,
) ([]ClientListResult, error) {
	targets, err := selectOrderedTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve client targets: %w", err)
	}

	results, err := runOnInstances(ctx, targets, a.useCase,
		func(ctx context.Context, service *client.Service, name string) (ClientListResult, error) {
			result, listErr := service.List(ctx)
			if listErr != nil {
				return ClientListResult{}, fmt.Errorf("list clients: %w", listErr)
			}

			return ClientListResult{Instance: name, Rows: result.Rows, Index: 0, InstanceCount: len(targets)}, nil
		},
	)

	for index := range results {
		results[index].Index = index
	}

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
func (a *ClientManagement) Update(
	ctx context.Context,
	selection Selection,
	settings client.Settings,
) ([]MutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		"update client",
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

// runMutation executes one mutation across all selected instances.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - operationName: operation label used in the aggregate error message.
//   - successMessage: per-instance success text reported on success.
//   - operation: domain mutation applied to each resolved instance service.
//
// Returns:
//   - []MutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *ClientManagement) runMutation(
	ctx context.Context,
	selection Selection,
	operationName string,
	successMessage string,
	operation clientMutationOperation,
) ([]MutationResult, error) {
	targets, err := selectTargets(ctx, selection, a.resolve)
	if err != nil {
		return nil, fmt.Errorf("resolve client targets: %w", err)
	}

	results, err := mutateInstances(ctx, targets, a.useCase, operation,
		func(name string) MutationResult {
			return MutationResult{Instance: name, Message: successMessage}
		},
	)
	if err != nil {
		return results, fmt.Errorf("%s across instances: %w", operationName, err)
	}

	return results, nil
}

// useCase creates the domain service for one instance.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - *client.Service: domain service wrapping the instance service.
//   - error: a wrapped service-construction error.
func (a *ClientManagement) useCase(cfg instance.Config) (*client.Service, error) {
	service, err := a.newService(cfg)
	if err != nil {
		return nil, fmt.Errorf("configure clients service: %w", err)
	}

	return client.NewService(service), nil
}

// newAdguardClientsService creates the production service factory.
//
// Parameters:
//   - cfg: instance connection settings.
//
// Returns:
//   - adguard.ClientsService: the configured public client service.
//   - error: a wrapped client-construction error.
//
//nolint:ireturn // The factory intentionally depends on the public service interface.
func newAdguardClientsService(cfg instance.Config) (adguard.ClientsService, error) {
	service, err := connection.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("build clients service: %w", err)
	}

	return service, nil
}
