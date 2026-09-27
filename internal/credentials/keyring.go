// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/zalando/go-keyring"
)

// SystemStore is the Store implementation backed by the operating system
// credential store.
//
// The backend is the macOS Keychain, the Linux and BSD Secret Service, or the
// Windows Credential Manager, depending on the platform. A Linux host without a
// running Secret Service session reports ErrStoreUnavailable rather than falling
// back to another store.
type SystemStore struct {
	// provider is the platform credential store used by every method.
	provider keyringProvider
}

// keyringProvider is the platform credential store surface used by SystemStore.
//
// The seam exists because the operating system credential store binds its
// provider to package-global state that offers no injectable client, and
// mutating that state would couple unrelated tests. Injecting a provider keeps
// error mapping testable without touching process-global state.
//
// The seam is unexported and unit tests substitute the in-package fake rather
// than a generated double, so mocks/keyringProvider.go is not part of the tree.
// Mockery has no per-interface exclusion setting, which means a future
// regeneration also emits that unused file and it can be removed again.
type keyringProvider interface {
	// Get returns the secret stored for a service and key.
	//
	// Parameters:
	//   - service: credential store namespace.
	//   - key: stable credential identity within the service.
	//
	// Returns:
	//   - string: the stored secret.
	//   - error: a platform error when the credential cannot be read.
	Get(service, key string) (string, error)
	// Set stores a secret for a service and key.
	//
	// Parameters:
	//   - service: credential store namespace.
	//   - key: stable credential identity within the service.
	//   - secret: secret to store.
	//
	// Returns:
	//   - error: a platform error when the credential cannot be written.
	Set(service, key, secret string) error
	// Delete removes the secret stored for a service and key.
	//
	// Parameters:
	//   - service: credential store namespace.
	//   - key: stable credential identity within the service.
	//
	// Returns:
	//   - error: a platform error when the credential cannot be removed.
	Delete(service, key string) error
	// DeleteAll removes every secret stored under a service.
	//
	// Parameters:
	//   - service: credential store namespace.
	//
	// Returns:
	//   - error: a platform error when the credentials cannot be removed.
	DeleteAll(service string) error
}

// systemProvider is the production provider backed by the operating system
// credential store of the running platform.
type systemProvider struct{}

// errRedactedSecret replaces a platform error that repeated the secret. Its
// message names the reason for the redaction without repeating the secret.
var errRedactedSecret = errors.New(
	"credential store error redacted because it repeated the secret",
)

// NewSystemStore creates a credential store backed by the operating system.
//
// Returns:
//   - *SystemStore: credential store over the platform provider.
func NewSystemStore() *SystemStore {
	return &SystemStore{provider: systemProvider{}}
}

// newSystemStoreWithProvider creates a credential store over an explicit
// provider.
//
// Parameters:
//   - provider: platform credential store used by every method.
//
// Returns:
//   - *SystemStore: credential store over the supplied provider.
func newSystemStoreWithProvider(provider keyringProvider) *SystemStore {
	return &SystemStore{provider: provider}
}

// Backend returns the name of the operating system credential store backend.
//
// Returns:
//   - string: KeyringBackend.
func (*SystemStore) Backend() string {
	return KeyringBackend
}

// Delete removes one stored credential.
//
// Parameters:
//   - ctx: context checked before the platform call.
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - error: a wrapped sentinel error when the identity is unusable, the
//     context is already done, or the platform call fails.
func (s *SystemStore) Delete(ctx context.Context, service, key string) error {
	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("delete credential %q from service %q: %w", key, service, err)
	}

	err = validateIdentity(service, key)
	if err != nil {
		return fmt.Errorf("delete credential %q from service %q: %w", key, service, err)
	}

	deleteErr := s.provider.Delete(service, key)
	if deleteErr != nil {
		return fmt.Errorf(
			"delete credential %q from service %q: %w",
			key,
			service,
			wrapStoreError("", deleteErr),
		)
	}

	return nil
}

// DeleteAll removes every stored credential of a service.
//
// Parameters:
//   - ctx: context checked before the platform call.
//   - service: credential store namespace.
//
// Returns:
//   - error: a wrapped sentinel error when the service is empty, the context is
//     already done, or the platform call fails.
func (s *SystemStore) DeleteAll(ctx context.Context, service string) error {
	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("delete credentials in service %q: %w", service, err)
	}

	err = validateService(service)
	if err != nil {
		return fmt.Errorf("delete credentials in service %q: %w", service, err)
	}

	deleteErr := s.provider.DeleteAll(service)
	if deleteErr != nil {
		return fmt.Errorf(
			"delete credentials in service %q: %w",
			service,
			wrapStoreError("", deleteErr),
		)
	}

	return nil
}

// Get returns the secret stored for a key within a service.
//
// A read involves no secret agh-cli holds, so a platform failure keeps its own
// message for diagnosis. Only a write can echo a secret, and only a write
// redacts.
//
// Parameters:
//   - ctx: context checked before the platform call.
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - string: the stored secret.
//   - error: a wrapped sentinel error when the identity is unusable, the
//     context is already done, or the platform call fails.
func (s *SystemStore) Get(ctx context.Context, service, key string) (string, error) {
	err := ctx.Err()
	if err != nil {
		return "", fmt.Errorf("get credential %q from service %q: %w", key, service, err)
	}

	err = validateIdentity(service, key)
	if err != nil {
		return "", fmt.Errorf("get credential %q from service %q: %w", key, service, err)
	}

	secret, getErr := s.provider.Get(service, key)
	if getErr != nil {
		return "", fmt.Errorf(
			"get credential %q from service %q: %w",
			key,
			service,
			wrapStoreError("", getErr),
		)
	}

	return secret, nil
}

// Set stores a secret for a key within a service.
//
// The secret is passed to the platform store unchanged and is never formatted
// into a returned error.
//
// Parameters:
//   - ctx: context checked before the platform call.
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//   - secret: secret to store.
//
// Returns:
//   - error: a wrapped sentinel error when the identity is unusable, the
//     context is already done, or the platform call fails.
func (s *SystemStore) Set(ctx context.Context, service, key, secret string) error {
	err := ctx.Err()
	if err != nil {
		return fmt.Errorf("set credential %q in service %q: %w", key, service, err)
	}

	err = validateIdentity(service, key)
	if err != nil {
		return fmt.Errorf("set credential %q in service %q: %w", key, service, err)
	}

	setErr := s.provider.Set(service, key, secret)
	if setErr != nil {
		return fmt.Errorf(
			"set credential %q in service %q: %w",
			key,
			service,
			wrapStoreError(secret, setErr),
		)
	}

	return nil
}

// Delete removes the secret stored for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - error: a platform error when the credential cannot be removed.
func (systemProvider) Delete(service, key string) error {
	err := keyring.Delete(service, key)
	if err != nil {
		return fmt.Errorf("platform delete: %w", err)
	}

	return nil
}

// DeleteAll removes every secret stored under a service.
//
// Parameters:
//   - service: credential store namespace.
//
// Returns:
//   - error: a platform error when the credentials cannot be removed.
func (systemProvider) DeleteAll(service string) error {
	err := keyring.DeleteAll(service)
	if err != nil {
		return fmt.Errorf("platform delete all: %w", err)
	}

	return nil
}

// Get returns the secret stored for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - string: the stored secret.
//   - error: a platform error when the credential cannot be read.
func (systemProvider) Get(service, key string) (string, error) {
	secret, err := keyring.Get(service, key)
	if err != nil {
		return "", fmt.Errorf("platform get: %w", err)
	}

	return secret, nil
}

// Set stores a secret for a service and key.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//   - secret: secret to store.
//
// Returns:
//   - error: a platform error when the credential cannot be written.
func (systemProvider) Set(service, key, secret string) error {
	err := keyring.Set(service, key, secret)
	if err != nil {
		return fmt.Errorf("platform set: %w", err)
	}

	return nil
}

// redactSecret hides a platform error that repeated the secret.
//
// Parameters:
//   - secret: secret that must never be reported.
//   - err: platform error to inspect.
//
// Returns:
//   - error: err when its message is safe to report, or errRedactedSecret
//     otherwise.
func redactSecret(secret string, err error) error {
	if secret == "" || !strings.Contains(err.Error(), secret) {
		return err
	}

	return errRedactedSecret
}

// validateIdentity rejects an unusable credential identity.
//
// Parameters:
//   - service: credential store namespace.
//   - key: stable credential identity within the service.
//
// Returns:
//   - error: ErrInvalidIdentity when the service or the key is empty.
func validateIdentity(service, key string) error {
	err := validateService(service)
	if err != nil {
		return fmt.Errorf("credential identity: %w", err)
	}

	if key == "" {
		return fmt.Errorf("%w: key is empty", ErrInvalidIdentity)
	}

	return nil
}

// validateService rejects an empty credential store namespace.
//
// Parameters:
//   - service: credential store namespace.
//
// Returns:
//   - error: ErrInvalidIdentity when the service is empty.
func validateService(service string) error {
	if service == "" {
		return fmt.Errorf("%w: service is empty", ErrInvalidIdentity)
	}

	return nil
}

// wrapStoreError converts a platform error into a project-owned error.
//
// A classified platform error becomes the matching project sentinel. Any other
// platform error becomes ErrStoreFailure or ErrStoreUnavailable, keeping the
// platform message for diagnosis unless it repeats the secret, in which case
// only the redacted description survives.
//
// Parameters:
//   - secret: secret involved in the operation, or an empty string when the
//     operation involved none.
//   - err: error returned by the platform credential store.
//
// Returns:
//   - error: an error wrapping a project-owned sentinel, or the redacted
//     platform error.
func wrapStoreError(secret string, err error) error {
	switch {
	case errors.Is(err, keyring.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, keyring.ErrSetDataTooBig):
		return ErrTooLarge
	case errors.Is(err, keyring.ErrUnsupportedPlatform):
		return fmt.Errorf("%w: %w", ErrStoreUnavailable, redactSecret(secret, err))
	default:
		return fmt.Errorf("%w: %w", ErrStoreFailure, redactSecret(secret, err))
	}
}
