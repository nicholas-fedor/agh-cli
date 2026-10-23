// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// Selection identifies the configured instances an operation targets.
//
// It carries only what the operator asked for. The application layer reads the
// configured instances from the run configuration, so the command layer never
// handles them.
type Selection struct {
	// Names contains explicit instance names in first-occurrence order.
	Names []string
	// All selects every configured instance when true.
	All bool
}

// InstanceListRequest contains the inputs for listing selected instances.
type InstanceListRequest struct {
	// All selects every configured instance when true.
	All bool
}

// InstanceAddRequest contains the inputs for adding one instance.
//
// The request carries no credentials. A username and a password are
// authentication details owned by the credential workflow, so an added instance
// is configured without them and the operator sets them afterwards.
type InstanceAddRequest struct {
	// Host is the AdGuard Home hostname or IP address.
	Host string
	// Name is the unique instance identifier.
	Name string
	// Scheme is the URL scheme used to contact the instance. An empty value
	// becomes HTTPS.
	Scheme string
}

// InstanceRemoveRequest contains the inputs for removing one instance.
type InstanceRemoveRequest struct {
	// Name is the instance identifier to remove.
	Name string
}

// InstanceRemoveResult reports the outcome of removing one instance.
//
// The result describes configuration state only. It never carries a secret or a
// value derived from one.
type InstanceRemoveResult struct {
	// Instance is the removed instance name.
	Instance string
	// Service is the credential store namespace the instance password belonged to.
	Service string
	// Key is the credential key the instance password was stored under. It is
	// empty when the instance kept no credential in the store.
	Key string
	// Removed reports whether a stored credential was deleted. A credential that
	// was already absent is not an error, so a repeated removal reports false.
	Removed bool
	// Shared reports that the stored credential was kept, because another
	// configured instance still reads its password through the same key.
	Shared bool
}

// ListInstances validates the configured instances and resolves instance names in
// selection order.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - request: selection mode.
//
// Returns:
//   - []instance.Config: selected configurations in execution order.
//   - error: a wrapped catalog or selection error.
func ListInstances(ctx context.Context, request InstanceListRequest) ([]instance.Config, error) {
	selected, err := selectInstances(ctx, Selection{Names: nil, All: request.All}, nil)
	if err != nil {
		return nil, fmt.Errorf("select instances: %w", err)
	}

	return selected, nil
}

// selectInstances applies selection policy to the configured instances.
//
// Parameters:
//   - ctx: context carrying the configuration of the run and governing
//     credential resolution.
//   - selection: the instances the operator selected.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - []instance.Config: selected configurations in selection order.
//   - error: a wrapped catalog, credential, or selection error.
func selectInstances(
	ctx context.Context,
	selection Selection,
	resolve instance.CredentialResolver,
) ([]instance.Config, error) {
	catalog, err := configuredCatalog(ctx, resolve)
	if err != nil {
		return nil, fmt.Errorf("prepare catalog: %w", err)
	}

	mode := instance.ExplicitOrDefaultSelection
	if selection.All {
		mode = instance.AllSelection
	}

	selected, err := catalog.Select(selection.Names, mode)
	if err != nil {
		return nil, fmt.Errorf("select from catalog: %w", err)
	}

	return selected, nil
}

// configuredCatalog builds the validated catalog of the configured instances.
//
// The catalog is ordered by instance name, so selecting every instance runs in
// the same order on every run. An instance whose stanza could not be decoded
// fails the catalog instead of being skipped, so a mistyped instance never lets
// a command fall back to another instance.
//
// Parameters:
//   - ctx: context carrying the configuration of the run and governing
//     credential resolution.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - instance.Catalog: the validated catalog, with resolved credentials when a
//     resolver is supplied.
//   - error: a wrapped configuration, validation, or credential error.
func configuredCatalog(
	ctx context.Context,
	resolve instance.CredentialResolver,
) (instance.Catalog, error) {
	manager, err := configFrom(ctx)
	if err != nil {
		return instance.Catalog{}, fmt.Errorf("build instance catalog: %w", err)
	}

	configs, err := manager.Configs()
	if err != nil {
		return instance.Catalog{}, fmt.Errorf("read configured instances: %w", err)
	}

	slices.SortFunc(configs, func(left, right instance.Config) int {
		return strings.Compare(left.Name, right.Name)
	})

	catalog, err := instance.NewCatalog(configs)
	if err != nil {
		return instance.Catalog{}, fmt.Errorf("build instance catalog: %w", err)
	}

	resolved, err := catalog.Resolve(ctx, resolve)
	if err != nil {
		return instance.Catalog{}, fmt.Errorf("resolve instance catalog: %w", err)
	}

	return resolved, nil
}

// configuredOrder returns the configured instance names in file order.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - []string: instance names in configuration-file order, or nil when ctx
//     carries no configuration.
func configuredOrder(ctx context.Context) []string {
	manager, err := configFrom(ctx)
	if err != nil {
		return nil
	}

	return manager.OrderedNames()
}

// AddInstance records one instance in the configuration file and saves it.
//
// The load, mutate, and save sequence runs here so the command layer never
// touches the configuration package. An absent file is created by the save, so
// the first instance does not require a pre-existing configuration. The added
// instance carries no credentials, so the save never writes an authentication
// detail the operator did not choose to set.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - request: the instance identity and connection settings.
//
// Returns:
//   - error: a wrapped error when no configuration is loaded, the instance is
//     already configured, or the file cannot be written.
func AddInstance(ctx context.Context, request InstanceAddRequest) error {
	manager, err := configFrom(ctx)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}

	err = manager.Add(
		request.Name,
		request.Host,
		request.Scheme,
	)
	if err != nil {
		return fmt.Errorf("register instance: %w", err)
	}

	err = manager.Save()
	if err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}

	return nil
}

// RemoveInstance deletes one instance from the configuration file, deletes the
// password it kept in the operating system credential store, and saves the file.
//
// The order is the guarantee. The stored credential is deleted first, and the
// configuration entry only afterwards, so no secret is ever left behind without
// the reference that made it reachable. A failed configuration write therefore
// leaves an instance whose credential is already gone, and repeating the command
// converges: the credential is then absent, the entry is removed, and the file is
// written. A failed credential delete does the opposite and keeps the instance,
// because removing the entry first would strand a secret nothing reports.
//
// Only a credential agh-cli owns is deleted. A mounted secret file, an
// environment variable, a plaintext password, and the unauthenticated source all
// resolve outside the credential store, so those instances are removed without
// contacting it and a host with no usable store is never blocked. A key another
// configured instance still reads is kept as well, so removing one instance never
// breaks another. An unknown instance is reported before the store is touched,
// because an instance that is not configured cannot own a credential.
//
// Parameters:
//   - ctx: context carrying the configuration of the run, checked before the
//     credential store calls.
//   - store: credential store holding the instance password. It must not be nil.
//   - request: the instance identifier.
//
// Returns:
//   - InstanceRemoveResult: the removed instance and the credential outcome.
//   - error: a wrapped error when no configuration is loaded, the
//     credential cannot be deleted, the instance is not configured, or the file
//     cannot be written.
func RemoveInstance(
	ctx context.Context,
	store credentials.Store,
	request InstanceRemoveRequest,
) (InstanceRemoveResult, error) {
	manager, err := configFrom(ctx)
	if err != nil {
		return InstanceRemoveResult{}, fmt.Errorf("read configuration: %w", err)
	}

	removal, err := credentials.NewManager(store, manager).RemoveInstancePassword(ctx, request.Name)
	result := InstanceRemoveResult{
		Instance: request.Name,
		Service:  removal.Service,
		Key:      removal.Key,
		Removed:  removal.Removed,
		Shared:   removal.Shared,
	}

	if err != nil {
		return result, fmt.Errorf(
			"remove credential of %q, leaving the instance configured: %w",
			request.Name,
			err,
		)
	}

	err = manager.Remove(request.Name)
	if err != nil {
		return result, fmt.Errorf("delete instance: %w", err)
	}

	err = manager.Save()
	if err != nil {
		return result, fmt.Errorf("write configuration: %w", err)
	}

	return result, nil
}
