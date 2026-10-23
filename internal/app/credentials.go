// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// NewCredentialStore returns the operating system credential store.
//
// The command layer never constructs a credential store itself, so the adapter
// is constructed here and handed to the use cases that write to it.
//
// Returns:
//   - *credentials.SystemStore: credential store over the platform provider.
func NewCredentialStore() *credentials.SystemStore {
	return credentials.NewSystemStore()
}

// NewCredentialResolver builds the production credential resolver.
//
// The namespace comes from the configuration of the run. The store is the
// operating system credential store, and the remaining sources are the process
// environment and mounted secret files.
//
// Construction only assembles dependencies. It never reads a secret and never
// probes the credential store, so building a resolver cannot block on an
// unavailable store or open a keyring session. A source is read when an instance
// that names it is selected, not here.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - *credentials.Resolver: resolver over the operating system credential
//     store, mounted secret files, and the process environment.
func NewCredentialResolver(ctx context.Context) *credentials.Resolver {
	return credentials.NewResolver(
		credentialService(ctx),
		credentials.NewSystemStore(),
		credentials.NewOSFileReader(),
		credentials.NewOSEnvReader(),
	)
}

// NewCredentialsCoordinator builds the production credential coordinator.
//
// Construction only assembles dependencies. The configuration comes from the
// run, which already loaded it, and the credential store is not probed, so
// building a coordinator cannot prompt, cannot block on an unavailable keyring,
// and cannot discard a pending change.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - *credentials.Manager: coordinator bound to the run configuration and the
//     operating system credential store.
//   - error: ErrNoRunConfig when ctx carries no configuration.
func NewCredentialsCoordinator(ctx context.Context) (*credentials.Manager, error) {
	manager, err := configFrom(ctx)
	if err != nil {
		return nil, fmt.Errorf("create credential coordinator: %w", err)
	}

	return credentials.NewManager(NewCredentialStore(), manager), nil
}

// credentialService returns the credential store namespace of the run.
//
// A context without a run configuration uses [credentials.DefaultService], the
// namespace an empty configuration declares.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - string: the configured credential store namespace.
func credentialService(ctx context.Context) string {
	manager, err := configFrom(ctx)
	if err != nil {
		return credentials.DefaultService
	}

	return manager.CredentialService()
}
