// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
)

// Store is the project-owned credential store contract.
//
// The contract hides the operating system credential store behind project-owned
// types and errors. Every method checks ctx before the synchronous platform call
// and returns immediately afterwards, because a goroutine wrapper could leave a
// platform operation running after cancellation returns. Implementations must
// never place a secret in an error.
type Store interface {
	// Get returns the secret stored for a key within a service.
	//
	// Parameters:
	//   - ctx: context checked before the platform call.
	//   - service: credential store namespace.
	//   - key: stable credential identity within the service.
	//
	// Returns:
	//   - string: the stored secret.
	//   - error: ErrNotFound when the credential is absent, or another
	//     project-owned error describing the failure.
	Get(ctx context.Context, service, key string) (string, error)
	// Set stores a secret for a key within a service.
	//
	// Parameters:
	//   - ctx: context checked before the platform call.
	//   - service: credential store namespace.
	//   - key: stable credential identity within the service.
	//   - secret: secret to store. It never appears in a returned error.
	//
	// Returns:
	//   - error: a project-owned error describing the failure.
	Set(ctx context.Context, service, key, secret string) error
	// Delete removes the secret stored for a key within a service.
	//
	// Parameters:
	//   - ctx: context checked before the platform call.
	//   - service: credential store namespace.
	//   - key: stable credential identity within the service.
	//
	// Returns:
	//   - error: a project-owned error describing the failure.
	Delete(ctx context.Context, service, key string) error
	// DeleteAll removes every secret stored under a service.
	//
	// Credentials of other applications are never touched.
	//
	// Parameters:
	//   - ctx: context checked before the platform call.
	//   - service: credential store namespace.
	//
	// Returns:
	//   - error: a project-owned error describing the failure.
	DeleteAll(ctx context.Context, service string) error
	// Backend returns the name of the credential store backend.
	//
	// Returns:
	//   - string: backend name reported by credential status output.
	Backend() string
}

// DefaultService is the credential store namespace used when a configuration
// sets none.
//
// The service is a global application namespace rather than per-instance state,
// so a credential written for one configuration lookup order is visible to every
// other lookup of the same operating system user.
const DefaultService = "agh-cli"

// KeyringBackend names the operating system credential store backend reported
// by credential status output.
const KeyringBackend = "keyring"

// Credential store errors.
var (
	// ErrInvalidIdentity indicates that a service namespace or credential key is
	// unusable.
	ErrInvalidIdentity = errors.New("credential store identity is invalid")
	// ErrNotFound indicates that the store holds no credential for the key.
	ErrNotFound = errors.New("credential not found")
	// ErrTooLarge indicates that a secret exceeds the size limit of the
	// credential store.
	ErrTooLarge = errors.New("credential exceeds store limit")
	// ErrStoreUnavailable indicates that no usable credential store exists, such
	// as a Linux host without a Secret Service session.
	ErrStoreUnavailable = errors.New("credential store unavailable")
	// ErrStoreFailure indicates that a credential store operation failed for a
	// reason the project does not classify further.
	ErrStoreFailure = errors.New("credential store operation failed")
)
