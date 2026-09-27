// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"time"

	"github.com/nicholas-fedor/agh-cli/internal/client"
	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/execution"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// ClientMutation contains the client values supplied by command flags.
type ClientMutation struct {
	// Name is the client name reported by AdGuard Home.
	Name string
	// IDs contains the identifiers associated with the client name.
	IDs []string
	// UseGlobalSettings reports whether global client settings are inherited.
	UseGlobalSettings bool
	// FilteringEnabled reports whether per-client filtering is enabled.
	FilteringEnabled bool
	// ParentalEnabled reports whether the parental control is enabled.
	ParentalEnabled bool
	// SafebrowsingEnabled reports whether the safe-browsing filter is enabled.
	SafebrowsingEnabled bool
}

// ClientSelection contains the instance-selection inputs for a client operation.
type ClientSelection struct {
	// Instances contains the configured instance mappings.
	Instances instance.Source
	// Names contains explicit instance names in first-occurrence order.
	Names []string
	// All selects every configured instance when true.
	All bool
	// ConfigPath identifies the configuration file used to order list results.
	ConfigPath string
}

// ClientListResult contains the successfully retrieved rows for one instance.
type ClientListResult struct {
	// Instance identifies the source instance.
	Instance string
	// Rows contains the retrieved clients in service order.
	Rows []client.Row
	// Index is the zero-based target position.
	Index int
	// InstanceCount is the number of selected targets.
	InstanceCount int
}

// ClientMutationResult contains the success message for one instance.
type ClientMutationResult struct {
	// Instance identifies the successful target.
	Instance string
	// Message is the operation-specific success text.
	Message string
}

// clientServiceFactory creates a client-management service for one instance.
type clientServiceFactory func(instance.Config) (adguard.ClientsService, error)

// clientMutationOperation executes one mutation against an instance service.
type clientMutationOperation func(
	context.Context,
	*client.Service,
	execution.Target[instance.Config],
) error

// ClientManagement coordinates client use cases across selected instances.
type ClientManagement struct {
	newService clientServiceFactory
	// resolve serves the configured credential source of every catalog entry.
	// A nil resolver leaves the configured password untouched, which keeps a
	// legacy plaintext configuration working.
	resolve instance.CredentialResolver
}

// clientRequestTimeout is the per-request timeout for constructed AdGuard clients.
const clientRequestTimeout = 30 * time.Second

// NewClientManagement creates production client-management wiring.
//
// The management resolves every configured credential source, so a keyring,
// mounted-file, or environment instance is served without the command layer
// reading a secret.
//
// Returns:
//   - *ClientManagement: management bound to the production service factory and
//     the production credential resolver.
func NewClientManagement() *ClientManagement {
	return NewClientManagementWithResolver(NewCredentialResolver())
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
//   - mutation: client values sent to every selected instance.
//
// Returns:
//   - []ClientMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *ClientManagement) Add(
	ctx context.Context,
	selection ClientSelection,
	mutation ClientMutation,
) ([]ClientMutationResult, error) {
	request := client.AddRequest{
		Name:                mutation.Name,
		IDs:                 mutation.IDs,
		UseGlobalSettings:   mutation.UseGlobalSettings,
		FilteringEnabled:    mutation.FilteringEnabled,
		ParentalEnabled:     mutation.ParentalEnabled,
		SafebrowsingEnabled: mutation.SafebrowsingEnabled,
	}

	results, err := a.runMutation(
		ctx,
		selection,
		"add client",
		"Added client "+mutation.Name,
		func(ctx context.Context, service *client.Service, _ execution.Target[instance.Config]) error {
			err := service.Add(ctx, request)
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
//   - []ClientMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *ClientManagement) Delete(
	ctx context.Context,
	selection ClientSelection,
	name string,
) ([]ClientMutationResult, error) {
	results, err := a.runMutation(
		ctx,
		selection,
		"delete client",
		"Deleted client "+name,
		func(ctx context.Context, service *client.Service, _ execution.Target[instance.Config]) error {
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
//   - []ClientListResult: retrieved rows in configuration order.
//   - error: a wrapped service or execution error.
func (a *ClientManagement) List(
	ctx context.Context,
	selection ClientSelection,
) ([]ClientListResult, error) {
	nextIndex := 0
	results, instanceCount, err := runClientOperation(
		ctx,
		selection,
		a.resolve,
		func(ctx context.Context, target execution.Target[instance.Config]) (ClientListResult, error) {
			index := nextIndex
			nextIndex++

			service, useCaseErr := a.useCase(target.Value)
			if useCaseErr != nil {
				return ClientListResult{}, fmt.Errorf("create client use case for %q: %w", target.Name, useCaseErr)
			}

			result, listErr := service.List(ctx)
			if listErr != nil {
				return ClientListResult{}, fmt.Errorf("list clients: %w", listErr)
			}

			return ClientListResult{Instance: target.Name, Rows: result.Rows, Index: index}, nil
		},
	)

	for index := range results {
		results[index].InstanceCount = instanceCount
	}

	orderedResults := orderClientListResults(results, selection)
	if err != nil {
		return orderedResults, fmt.Errorf("list clients across instances: %w", err)
	}

	return orderedResults, nil
}

// Update applies a client patch to every selected instance.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - mutation: client values sent to every selected instance.
//
// Returns:
//   - []ClientMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *ClientManagement) Update(
	ctx context.Context,
	selection ClientSelection,
	mutation ClientMutation,
) ([]ClientMutationResult, error) {
	request := client.UpdateRequest{
		Name:                mutation.Name,
		IDs:                 mutation.IDs,
		UseGlobalSettings:   mutation.UseGlobalSettings,
		FilteringEnabled:    mutation.FilteringEnabled,
		ParentalEnabled:     mutation.ParentalEnabled,
		SafebrowsingEnabled: mutation.SafebrowsingEnabled,
	}

	results, err := a.runMutation(
		ctx,
		selection,
		"update client",
		"Updated client "+mutation.Name,
		func(ctx context.Context, service *client.Service, _ execution.Target[instance.Config]) error {
			err := service.Update(ctx, request)
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
//   - []ClientMutationResult: one success message per successful instance.
//   - error: a wrapped service or execution error.
func (a *ClientManagement) runMutation(
	ctx context.Context,
	selection ClientSelection,
	operationName string,
	successMessage string,
	operation clientMutationOperation,
) ([]ClientMutationResult, error) {
	results, _, err := runClientOperation(
		ctx,
		selection,
		a.resolve,
		func(ctx context.Context, target execution.Target[instance.Config]) (ClientMutationResult, error) {
			service, useCaseErr := a.useCase(target.Value)
			if useCaseErr != nil {
				return ClientMutationResult{}, fmt.Errorf("create client use case for %q: %w", target.Name, useCaseErr)
			}

			operationErr := operation(ctx, service, target)
			if operationErr != nil {
				return ClientMutationResult{}, fmt.Errorf("execute mutation for %q: %w", target.Name, operationErr)
			}

			return ClientMutationResult{Instance: target.Name, Message: successMessage}, nil
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
//   - *domainclient.Service: domain service wrapping the instance service.
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
	service, err := newAdguardClientsServiceWithHTTPClient(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("build clients service: %w", err)
	}

	return service, nil
}

// newAdguardClientsServiceWithHTTPClient creates a public AdGuard client for an instance.
//
// Parameters:
//   - cfg: instance connection settings.
//   - httpClient: transport override; nil selects the default transport.
//
// Returns:
//   - *adguard.Client: the configured public client.
//   - error: a wrapped client-construction error.
func newAdguardClientsServiceWithHTTPClient(
	cfg instance.Config,
	httpClient *http.Client,
) (*adguard.Client, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "https"
	}

	baseURL := (&url.URL{Scheme: scheme, Host: cfg.Host}).String()
	options := []adguard.Option{adguard.WithRequestTimeout(clientRequestTimeout)}
	if httpClient != nil {
		options = append(options, adguard.WithHTTPClient(httpClient))
	}

	if cfg.Username != "" || cfg.Password != "" {
		options = append(options, adguard.WithBasicAuth(cfg.Username, cfg.Password))
	}

	service, err := adguard.NewClient(baseURL, options...)
	if err != nil {
		return nil, fmt.Errorf("configure client: %w", err)
	}

	return service, nil
}

// runClientOperation executes one operation across all selected instances.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//   - operation: per-instance operation producing one result value.
//
// Returns:
//   - []T: one result per successful instance in execution order.
//   - int: the number of selected instances.
//   - error: a wrapped resolution or execution error.
func runClientOperation[T any](
	ctx context.Context,
	selection ClientSelection,
	resolve instance.CredentialResolver,
	operation func(context.Context, execution.Target[instance.Config]) (T, error),
) ([]T, int, error) {
	targets, err := clientTargets(ctx, selection, resolve)
	if err != nil {
		return nil, 0, fmt.Errorf("resolve client targets: %w", err)
	}

	results, count, err := runAcrossTargets(ctx, targets, "client operation", operation)
	if err != nil {
		return results, count, fmt.Errorf("run client operation: %w", err)
	}

	return results, count, nil
}

// clientTargets resolves instance configurations in operation order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - selection: instance-selection inputs for the operation.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []execution.Target[instance.Config]: resolved targets in execution order.
//   - error: a wrapped catalog or selection error.
func clientTargets(
	ctx context.Context,
	selection ClientSelection,
	resolve instance.CredentialResolver,
) ([]execution.Target[instance.Config], error) {
	catalog, err := instance.CatalogFromSourceResolved(ctx, selection.Instances, resolve)
	if err != nil {
		return nil, fmt.Errorf("build client catalog: %w", err)
	}

	mode := instance.ExplicitOrDefaultSelection
	if selection.All {
		mode = instance.AllSelection
	}

	selected, err := catalog.Select(selection.Names, mode)
	if err != nil {
		return nil, fmt.Errorf("select client targets: %w", err)
	}

	targets := make([]execution.Target[instance.Config], 0, len(selected))
	for _, cfg := range selected {
		targets = append(targets, execution.Target[instance.Config]{Name: cfg.Name, Value: cfg})
	}

	return targets, nil
}

// orderClientListResults applies configuration order to successful list results.
//
// Parameters:
//   - results: retrieved rows keyed by instance in completion order.
//   - selection: instance-selection inputs providing the configuration path.
//
// Returns:
//   - []ClientListResult: results in configuration order, or sorted by instance
//     name when the configured order is unavailable.
func orderClientListResults(
	results []ClientListResult,
	selection ClientSelection,
) []ClientListResult {
	byInstance := make(map[string]ClientListResult, len(results))
	for _, result := range results {
		byInstance[result.Instance] = result
	}

	names, ordered := configuredClientOrder(selection.ConfigPath)
	if !ordered {
		names = slices.Sorted(maps.Keys(byInstance))
	}

	orderedResults := make([]ClientListResult, 0, len(byInstance))
	for _, name := range names {
		if result, ok := byInstance[name]; ok {
			orderedResults = append(orderedResults, result)
		}
	}

	return orderedResults
}

// configuredClientOrder loads instance names in configuration-file order.
//
// Parameters:
//   - configPath: path to the configuration file; an empty path loads nothing.
//
// Returns:
//   - []string: instance names in configuration-file order.
//   - bool: false when the configuration order is unavailable.
func configuredClientOrder(configPath string) ([]string, bool) {
	if configPath == "" {
		return nil, false
	}

	manager, err := config.Load(configPath)
	if err != nil {
		return nil, false
	}

	return manager.OrderedNames(), true
}
