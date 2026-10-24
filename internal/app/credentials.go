// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// credentialStoreKey is the context key carrying the credential store of a run.
type credentialStoreKey struct{}

// WithCredentialStore returns a copy of ctx whose credential use cases use store.
//
// A run that attaches no store uses the operating system credential store. A
// test attaches its own store, so the use cases run without one and can never
// reach the host credential store.
//
// Parameters:
//   - ctx: context of the run.
//   - store: credential store the use cases of the run read and write.
//
// Returns:
//   - [context.Context]: ctx carrying store.
func WithCredentialStore(ctx context.Context, store credentials.Store) context.Context {
	return context.WithValue(ctx, credentialStoreKey{}, store)
}

// NewCredentialResolver builds the production credential resolver.
//
// The namespace comes from the configuration of the run. The store is the
// credential store of the run, and the remaining sources are the process
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
//   - *credentials.Resolver: resolver over the credential store, mounted secret
//     files, and the process environment.
func NewCredentialResolver(ctx context.Context) *credentials.Resolver {
	return credentials.NewResolver(
		credentialService(ctx),
		credentialStore(ctx),
		credentials.NewOSFileReader(),
		credentials.NewOSEnvReader(),
	)
}

// MigrateCredentials moves legacy plaintext passwords into the credential store.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - request: migration inputs, including the dry-run selection.
//
// Returns:
//   - [credentials.MigrationReport]: one outcome per legacy instance.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func MigrateCredentials(
	ctx context.Context,
	request credentials.MigrationRequest,
) (credentials.MigrationReport, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.MigrationReport{}, fmt.Errorf("%w", err)
	}

	result, err := manager.Migrate(ctx, request)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// SetPassword stores one instance password and points the instance at it.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - name: configured instance name.
//   - key: credential key, or an empty string for the configured key.
//   - secret: password read from the operator. It never appears in a result or
//     an error.
//
// Returns:
//   - [credentials.PasswordSetResult]: the written identity and whether it
//     replaced a credential.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func SetPassword(
	ctx context.Context,
	name, key, secret string,
) (credentials.PasswordSetResult, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.PasswordSetResult{}, fmt.Errorf("%w", err)
	}

	result, err := manager.SetPassword(ctx, name, key, secret)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// ClearPassword removes the stored password of one instance.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - name: configured instance name.
//
// Returns:
//   - [credentials.PasswordClearResult]: the cleared identity and whether a
//     credential was removed.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func ClearPassword(ctx context.Context, name string) (credentials.PasswordClearResult, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.PasswordClearResult{}, fmt.Errorf("%w", err)
	}

	result, err := manager.ClearPassword(ctx, name)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// ClearAllPasswords removes every password of the configured service.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - [credentials.PasswordClearResult]: the cleared service.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func ClearAllPasswords(ctx context.Context) (credentials.PasswordClearResult, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.PasswordClearResult{}, fmt.Errorf("%w", err)
	}

	result, err := manager.ClearAllPasswords(ctx)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// StatusPassword reports credential store state for the named instances.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - names: instance names to inspect, or an empty slice for every instance.
//
// Returns:
//   - [credentials.PasswordReport]: the backend, the service, and one entry per
//     instance.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func StatusPassword(ctx context.Context, names []string) (credentials.PasswordReport, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.PasswordReport{}, fmt.Errorf("%w", err)
	}

	result, err := manager.StatusPassword(ctx, names)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// SetUsername records the administrator username of one instance.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - name: configured instance name.
//   - username: administrator username to record.
//
// Returns:
//   - [credentials.UsernameResult]: the instance and whether the file was
//     rewritten.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func SetUsername(ctx context.Context, name, username string) (credentials.UsernameResult, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.UsernameResult{}, fmt.Errorf("%w", err)
	}

	result, err := manager.SetUsername(name, username)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// ClearUsername removes the administrator username of one instance.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - name: configured instance name.
//
// Returns:
//   - [credentials.UsernameResult]: the instance and whether the file was
//     rewritten.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func ClearUsername(ctx context.Context, name string) (credentials.UsernameResult, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.UsernameResult{}, fmt.Errorf("%w", err)
	}

	result, err := manager.ClearUsername(name)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// StatusUsername reports the configured username of the named instances.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//   - names: instance names to inspect, or an empty slice for every instance.
//
// Returns:
//   - [credentials.UsernameReport]: one entry per instance in configuration
//     order.
//   - error: the use case error, or a wrapped error when ctx carries no
//     configuration.
func StatusUsername(ctx context.Context, names []string) (credentials.UsernameReport, error) {
	manager, err := credentialManager(ctx)
	if err != nil {
		return credentials.UsernameReport{}, fmt.Errorf("%w", err)
	}

	result, err := manager.StatusUsername(names)
	if err != nil {
		return result, fmt.Errorf("%w", err)
	}

	return result, nil
}

// credentialManager builds the credential use cases of the run.
//
// Construction only assembles dependencies. The configuration comes from the
// run, which already loaded it, and the credential store is not probed, so
// building the manager cannot prompt, cannot block on an unavailable keyring,
// and cannot discard a pending change.
//
// Parameters:
//   - ctx: context carrying the configuration of the run.
//
// Returns:
//   - *credentials.Manager: use cases bound to the run configuration and the
//     credential store of the run.
//   - error: a wrapped [ErrNoRunConfig] when ctx carries no configuration.
func credentialManager(ctx context.Context) (*credentials.Manager, error) {
	manager, err := configFrom(ctx)
	if err != nil {
		return nil, fmt.Errorf("create credential coordinator: %w", err)
	}

	return credentials.NewManager(credentialStore(ctx), manager), nil
}

// credentialStore returns the credential store of the run.
//
// Parameters:
//   - ctx: context of the run.
//
// Returns:
//   - [credentials.Store]: the store attached by [WithCredentialStore], or the
//     operating system credential store when none is attached.
//
//nolint:ireturn // The run may carry any store implementation, including a test fake.
func credentialStore(ctx context.Context) credentials.Store {
	store, ok := ctx.Value(credentialStoreKey{}).(credentials.Store)
	if ok && store != nil {
		return store
	}

	return credentials.NewSystemStore()
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
