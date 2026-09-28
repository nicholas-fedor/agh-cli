// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"

	"github.com/spf13/viper"

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

// RemoveInstance deletes one instance from the configuration file and saves it.
//
// The stored credential of the instance is deliberately left alone. Deleting a
// configuration entry must not depend on an external credential store, so
// operators clear credentials explicitly.
//
// Parameters:
//   - request: the instance identifier and configuration file path.
//
// Returns:
//   - error: a wrapped error when the configuration cannot be loaded, the
//     instance is not configured, or the file cannot be written.
func RemoveInstance(request InstanceRemoveRequest) error {
	manager, err := LoadConfig(request.ConfigPath)
	if err != nil {
		return fmt.Errorf("read configuration: %w", err)
	}

	err = manager.Remove(request.Name)
	if err != nil {
		return fmt.Errorf("delete instance: %w", err)
	}

	err = manager.Save()
	if err != nil {
		return fmt.Errorf("write configuration: %w", err)
	}

	return nil
}
