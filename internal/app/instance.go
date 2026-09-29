// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// InstanceListRequest contains the inputs for listing selected instances.
type InstanceListRequest struct {
	// Instances contains the configured instance mappings.
	Instances instance.Source
	// All selects every configured instance when true.
	All bool
}

// InstanceAddRequest contains the inputs for adding one instance.
//
// The request carries no credentials. A username and a password are
// authentication details owned by the credential workflow, so an added instance
// is configured without them and the operator sets them afterwards.
type InstanceAddRequest struct {
	// ConfigPath is the configuration file the instance is appended to.
	ConfigPath string
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
	// ConfigPath is the configuration file the instance is removed from.
	ConfigPath string
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

// viperInstancesKey is the configuration path of the instance mapping.
const viperInstancesKey = "instances"

// InstanceSource reads the configured instance mappings as a typed source.
//
// The configuration loader yields an untyped value, so the read is converted and
// reported here instead of at every command that selects an instance. A mistyped
// instance stanza therefore fails with the configuration that caused it, and no
// command has to assert the loader's shape on its own.
//
// Returns:
//   - instance.Source: the configured instance mappings, or an empty source when
//     the configuration declares none.
//   - error: a wrapped conversion error when the configured value is not an
//     instance mapping.
func InstanceSource() (instance.Source, error) {
	source, err := instance.SourceFromValue(viper.Get(viperInstancesKey))
	if err != nil {
		return nil, fmt.Errorf("read %q configuration: %w", viperInstancesKey, err)
	}

	return source, nil
}

// ListInstances validates the configured instances and resolves instance names in
// selection order.
//
// Parameters:
//   - request: configured instance mappings and selection mode.
//
// Returns:
//   - []instance.Config: selected configurations in execution order.
//   - error: a wrapped catalog or selection error.
func ListInstances(request InstanceListRequest) ([]instance.Config, error) {
	catalog, err := instance.CatalogFromSource(request.Instances)
	if err != nil {
		return nil, fmt.Errorf("build instance catalog: %w", err)
	}

	mode := instance.ExplicitOrDefaultSelection
	if request.All {
		mode = instance.AllSelection
	}

	selected, err := catalog.Select(nil, mode)
	if err != nil {
		return nil, fmt.Errorf("select instances: %w", err)
	}

	return selected, nil
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
//   - request: the instance identity, connection settings, and configuration
//     file path.
//
// Returns:
//   - error: a wrapped error when the configuration cannot be loaded, the
//     instance is already configured, or the file cannot be written.
func AddInstance(request InstanceAddRequest) error {
	manager, err := LoadConfig(request.ConfigPath)
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
//   - ctx: context checked before the credential store calls.
//   - store: credential store holding the instance password. It must not be nil.
//   - request: the instance identifier and configuration file path.
//
// Returns:
//   - InstanceRemoveResult: the removed instance and the credential outcome.
//   - error: a wrapped error when the configuration cannot be loaded, the
//     credential cannot be deleted, the instance is not configured, or the file
//     cannot be written.
func RemoveInstance(
	ctx context.Context,
	store credentials.Store,
	request InstanceRemoveRequest,
) (InstanceRemoveResult, error) {
	manager, err := LoadConfig(request.ConfigPath)
	if err != nil {
		return InstanceRemoveResult{}, fmt.Errorf("read configuration: %w", err)
	}

	result, err := removeStoredInstancePassword(ctx, store, manager, request.Name)
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

// removeStoredInstancePassword deletes the credential store entry holding the
// password of one configured instance.
//
// The credential is reached through the configuration, not through the instance
// name, so only an entry the instance declared is deleted. An instance whose
// source resolves elsewhere leaves the store untouched.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - store: credential store holding the instance password.
//   - local: configuration supplying the credential service and the instance set.
//   - name: configured instance being removed.
//
// Returns:
//   - InstanceRemoveResult: the credential identity and whether an entry was
//     deleted.
//   - error: a wrapped error when the store cannot be read or the delete fails.
func removeStoredInstancePassword(
	ctx context.Context,
	store credentials.Store,
	local *config.Manager,
	name string,
) (InstanceRemoveResult, error) {
	result := InstanceRemoveResult{Instance: name, Service: credentialServiceOf(local.Credentials())}

	// An unknown instance owns no credential, so the store is left alone and the
	// removal itself reports the unknown name.
	cfg, exists := local.Instances()[name]
	if !exists {
		return result, nil
	}

	key, stored := keyringCredentialKey(cfg)
	if !stored {
		return result, nil
	}

	result.Key = key

	if otherInstanceReferencesKey(local.Instances(), name, key) {
		result.Shared = true

		return result, nil
	}

	removed, err := deleteStoredCredential(ctx, store, result.Service, key)
	if err != nil {
		return result, fmt.Errorf(
			"delete credential %q in service %q: %w",
			key,
			result.Service,
			err,
		)
	}

	result.Removed = removed

	return result, nil
}
