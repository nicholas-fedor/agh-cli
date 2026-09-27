// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// CredentialConfig is the configuration surface required by the credential use
// cases.
//
// [*config.Manager] satisfies the interface. Narrowing the dependency keeps the
// coordinator testable with a fake and keeps it from depending on instance
// mutation or persistence policy it does not own.
type CredentialConfig interface {
	// Credentials returns the effective top-level credential settings.
	//
	// Returns:
	//   - config.CredentialsSettings: the credential store settings.
	Credentials() config.CredentialsSettings
	// Instances returns a snapshot of the configured instances.
	//
	// Returns:
	//   - map[string]instance.Config: an independent configuration snapshot.
	Instances() map[string]instance.Config
	// OrderedNames returns the instance names in configuration order.
	//
	// Returns:
	//   - []string: names in configuration order.
	OrderedNames() []string
	// SetCredential records the credential reference of one instance in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//   - ref: credential reference to store.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	SetCredential(name string, ref instance.CredentialRef) error
	// ClearPassword removes the plaintext password of one instance in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	ClearPassword(name string) error
	// ClearCredential removes the credential reference of one instance in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	ClearCredential(name string) error
	// Save writes the current in-memory configuration to its source file.
	//
	// Returns:
	//   - error: a wrapped error when the configuration cannot be written.
	Save() error
}

// Credentials coordinates credential use cases across the operating system
// credential store and the local configuration.
//
// The coordinator owns credential policy. The command layer owns presentation
// and secret input, so every method accepts a secret as an already-read string
// and never reads standard input itself. No result, message, or error returned
// by this type carries a secret or a value derived from one.
type Credentials struct {
	// store is the credential store written by set, clear, and migrate.
	store credentials.Store
	// local is the configuration supplying the credential service and the
	// instance set.
	local CredentialConfig
}

// SetResult reports the outcome of storing one credential.
//
// The result describes configuration state only. It never carries the secret or a
// value derived from it.
type SetResult struct {
	// Instance is the instance whose credential was written and now referenced.
	Instance string
	// Backend is the credential store backend name.
	Backend string
	// Service is the credential store namespace written to.
	Service string
	// Key is the credential key written to and referenced by the instance.
	Key string
	// Replaced reports whether the write overwrote an existing credential.
	Replaced bool
	// Saved reports whether the configuration file was rewritten. A false value
	// means the plaintext password is still on disk and the write is retryable.
	Saved bool
}

// ClearResult reports the outcome of clearing one credential or one service.
//
// The result describes configuration state only. It never carries the secret or a
// value derived from it.
type ClearResult struct {
	// Instance is the cleared instance name. It is empty for a service-wide
	// clear.
	Instance string
	// Service is the credential store namespace that was cleared.
	Service string
	// Key is the cleared credential key. It is empty for a service-wide clear.
	Key string
	// Removed reports whether a stored credential was deleted. Clearing an
	// absent credential is not an error, so a repeated clear reports false.
	Removed bool
	// All reports whether every credential of the service was cleared.
	All bool
	// Saved reports whether the configuration file was rewritten. A false value
	// means the file still references a credential that was already deleted.
	Saved bool
}

// viperCredentialServiceKey is the configuration path of the credential store
// namespace read from the Viper configuration.
const viperCredentialServiceKey = "credentials.service"

// ErrExternalCredentialSource reports a clear request for an instance whose
// credential belongs to another system.
//
// A mounted secret file and an environment variable are owned by Docker,
// Kubernetes, systemd, Vault, or the operator, so agh-cli can neither delete the
// secret nor detach an instance from it without silently changing which password
// the instance will use. The operator owns that change, by editing the
// configuration.
var ErrExternalCredentialSource = errors.New(
	"credential belongs to an external source, not the credential store",
)

// NewCredentialResolver builds the production credential resolver.
//
// The namespace comes from the Viper configuration, because the root command
// reads the configuration file into Viper before any subcommand runs. The store
// is the operating system credential store, and the remaining sources are the
// process environment and mounted secret files.
//
// Construction only assembles dependencies. It never reads a secret and never
// probes the credential store, so building a resolver cannot block on an
// unavailable store or open a keyring session. A source is read when an instance
// that names it is selected, not here.
//
// Returns:
//   - *credentials.Resolver: resolver over the operating system credential
//     store, mounted secret files, and the process environment.
func NewCredentialResolver() *credentials.Resolver {
	return credentials.NewResolver(
		credentialService(),
		credentials.NewSystemStore(),
		credentials.NewOSFileReader(),
		credentials.NewOSEnvReader(),
	)
}

// NewCredentials creates a credential coordinator.
//
// Parameters:
//   - store: credential store backing set, clear, status, and migrate. It must
//     not be nil.
//   - local: configuration supplying the credential service and the instance
//     set. It must not be nil.
//
// Returns:
//   - *Credentials: coordinator bound to the supplied dependencies.
func NewCredentials(store credentials.Store, local CredentialConfig) *Credentials {
	return &Credentials{store: store, local: local}
}

// Clear removes the stored credential of one configured instance and detaches the
// instance from its credential source.
//
// The order is the guarantee. The credential store entry is deleted first, and
// the configuration reference is only removed afterwards, so the configuration
// never stops pointing at a secret that still exists.
//
// Only the credential store is clearable. An instance reading a mounted secret file
// or an environment variable is refused with [ErrExternalCredentialSource] before
// the store or the configuration is touched, because agh-cli owns neither that
// secret nor the decision to stop using it. Detaching such an instance would
// silently change which password the instance sends, so the operator makes that
// change by editing the configuration. A keyring instance, an explicit plaintext
// instance, and a legacy instance without a credential reference all remain
// clearable.
//
// Removing an instance from the configuration does not remove its stored
// credential, so clearing is always explicit. Clearing an absent credential is
// not an error, which makes a repeated clear safe. The reference removal is
// idempotent for the same reason, so a repeated clear also converges.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - name: configured instance name supplying the credential key.
//
// Returns:
//   - ClearResult: the cleared identity, whether a credential was removed, and
//     whether the configuration was rewritten.
//   - error: a wrapped [ErrExternalCredentialSource] for a file or environment
//     instance, a wrapped config.ErrInstanceNotFound for an unknown name, or a
//     wrapped error when the store rejects the read or the delete, or the
//     configuration cannot be written.
func (a *Credentials) Clear(ctx context.Context, name string) (ClearResult, error) {
	cfg, exists := a.local.Instances()[name]
	if !exists {
		return ClearResult{}, fmt.Errorf("instance %q %w", name, config.ErrInstanceNotFound)
	}

	source, _ := credentialIdentity(cfg)
	if isExternalSource(source) {
		return ClearResult{}, fmt.Errorf(
			"clear credential of %q: %w: source is %q",
			name,
			ErrExternalCredentialSource,
			source,
		)
	}

	service := a.service()
	credentialKey := credentialKeyFor(cfg, "")

	result := ClearResult{Instance: name, Service: service, Key: credentialKey}

	removed, err := a.deleteStoredCredential(ctx, service, credentialKey)
	if err != nil {
		return result, fmt.Errorf("clear credential %q: %w", credentialKey, err)
	}

	result.Removed = removed

	err = a.local.ClearCredential(name)
	if err != nil {
		return result, fmt.Errorf("remove credential reference of %q: %w", name, err)
	}

	result.Saved, err = a.save()
	if err != nil {
		return result, fmt.Errorf("clear credential %q: %w", credentialKey, err)
	}

	return result, nil
}

// ClearAll removes every credential stored under the configured service.
//
// Only the configured service is affected, so credentials belonging to other
// applications are never touched. The configuration is deliberately left alone:
// a credential reference survives the deletion, so every affected instance is
// detached with an explicit clear instead of a silent change of source.
//
// Parameters:
//   - ctx: context checked before the credential store call.
//
// Returns:
//   - ClearResult: the cleared service.
//   - error: a wrapped error when the store rejects the delete.
func (a *Credentials) ClearAll(ctx context.Context) (ClearResult, error) {
	service := a.service()

	err := a.store.DeleteAll(ctx, service)
	if err != nil {
		return ClearResult{}, fmt.Errorf(
			"delete credentials in service %q: %w",
			service,
			err,
		)
	}

	return ClearResult{Service: service, Removed: true, All: true}, nil
}

// Set stores one credential in the operating system credential store and points
// the configured instance at it.
//
// The order is the guarantee. The credential store write happens first, and the
// configuration only changes after a successful write, so a failed write leaves
// the instance exactly as it was and the legacy plaintext password keeps working.
// After a successful write the instance records the credential reference, drops
// its legacy plaintext password, and the configuration is written once.
//
// A configured instance must exist, because the instance name is the default
// credential key and a key belonging to no instance would be an orphan secret.
//
// A configuration write failure leaves the plaintext password on disk, and the
// returned error reports it. Repeating the write converges: the credential store
// already holds the key, so the second attempt reports Replaced and saves
// successfully.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - name: configured instance name supplying the default credential key.
//   - key: credential key, or an empty string to use the configured key.
//   - secret: secret read by the command layer. It never appears in a result or
//     an error.
//
// Returns:
//   - SetResult: the written identity, whether it replaced a credential, and
//     whether the configuration was rewritten.
//   - error: a wrapped error when the instance is unknown, the store rejects the
//     read or the write, or the configuration cannot be written.
func (a *Credentials) Set(
	ctx context.Context,
	name string,
	key string,
	secret string,
) (SetResult, error) {
	service := a.service()

	credentialKey, err := a.credentialKey(name, key)
	if err != nil {
		return SetResult{}, fmt.Errorf("resolve credential key for %q: %w", name, err)
	}

	replaced, err := a.stored(ctx, service, credentialKey)
	if err != nil {
		return SetResult{}, fmt.Errorf("check credential %q: %w", credentialKey, err)
	}

	err = a.storeCredential(ctx, service, name, credentialKey, secret)
	if err != nil {
		return SetResult{}, fmt.Errorf("set credential %q: %w", credentialKey, err)
	}

	result := SetResult{
		Instance: name,
		Backend:  a.store.Backend(),
		Service:  service,
		Key:      credentialKey,
		Replaced: replaced,
	}

	result.Saved, err = a.save()
	if err != nil {
		return result, fmt.Errorf("set credential %q: %w", credentialKey, err)
	}

	return result, nil
}

// credentialKey resolves the credential key written for one configured instance.
//
// Parameters:
//   - name: configured instance name.
//   - key: explicit credential key, or an empty string.
//
// Returns:
//   - string: the credential key.
//   - error: a wrapped config.ErrInstanceNotFound when the instance is unknown.
func (a *Credentials) credentialKey(name, key string) (string, error) {
	cfg, exists := a.local.Instances()[name]
	if !exists {
		return "", fmt.Errorf("instance %q %w", name, config.ErrInstanceNotFound)
	}

	return credentialKeyFor(cfg, key), nil
}

// credentialKeyFor resolves the credential key of one already-resolved instance.
//
// An explicit key wins, a configured keyring key is reused, and an empty key falls
// back to the instance name. The fallback matches the keyring key default applied
// by instance validation, and the key never embeds a host, so a host change does
// not require re-entering a password.
//
// Parameters:
//   - cfg: configured instance supplying the fallback identity.
//   - key: explicit credential key, or an empty string.
//
// Returns:
//   - string: the credential key for the instance.
func credentialKeyFor(cfg instance.Config, key string) string {
	if key != "" {
		return key
	}

	if cfg.Credential != nil && cfg.Credential.Source == instance.KeyringSource {
		if cfg.Credential.Key != "" {
			return cfg.Credential.Key
		}
	}

	return cfg.Name
}

// deleteStoredCredential removes one credential store entry when it is present.
//
// An absent entry is not an error, so a repeated clear converges. The read runs
// before the delete, so an unusable store is reported before a delete is
// attempted, and an entry is never deleted without the caller naming it.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - service: credential store namespace.
//   - key: credential key to remove.
//
// Returns:
//   - bool: true when an entry was deleted.
//   - error: a wrapped error when the store cannot be read or the delete fails.
func (a *Credentials) deleteStoredCredential(
	ctx context.Context,
	service string,
	key string,
) (bool, error) {
	_, err := a.store.Get(ctx, service, key)
	if errors.Is(err, credentials.ErrNotFound) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("read store: %w", err)
	}

	err = a.store.Delete(ctx, service, key)
	if err != nil {
		return false, fmt.Errorf("delete store entry: %w", err)
	}

	return true, nil
}

// save writes the in-memory configuration to its source file.
//
// Every use case that changes the configuration calls this once, so a rotation, a
// clear, and a migration never leave a partially written file behind.
//
// Returns:
//   - bool: true when the configuration file was rewritten.
//   - error: a wrapped error when the configuration could not be written. The file
//     then still holds its previous content, so repeating the operation is safe.
func (a *Credentials) save() (bool, error) {
	err := a.local.Save()
	if err != nil {
		return false, fmt.Errorf("save credential configuration: %w", err)
	}

	return true, nil
}

// service returns the credential store namespace used by every use case.
//
// An empty configured service falls back to [credentials.DefaultService],
// because the namespace must never be empty.
//
// Returns:
//   - string: the credential store namespace.
func (a *Credentials) service() string {
	service := a.local.Credentials().Service
	if service == "" {
		return credentials.DefaultService
	}

	return service
}

// credentialService returns the credential store namespace from the Viper
// configuration.
//
// The Viper configuration and the loaded configuration file are two views of the
// same document, and both fall back to [credentials.DefaultService] when the
// document sets no namespace.
//
// Returns:
//   - string: the configured credential store namespace.
func credentialService() string {
	service := viper.GetString(viperCredentialServiceKey)
	if service == "" {
		return credentials.DefaultService
	}

	return service
}

// storeCredential writes one secret to the credential store and then points the
// instance at it in memory.
//
// The order is the guarantee. The credential store write happens first, and the
// configuration changes only follow a successful write, so a failed write leaves
// the instance exactly as it was, including its legacy plaintext password. The
// caller persists the configuration, because a migration saves once for every
// instance while a single write saves for itself.
//
// The returned error names the failing step rather than the instance, because the
// caller already reports the instance and the resolved key alongside the outcome.
//
// Parameters:
//   - ctx: context checked before the credential store call.
//   - service: credential store namespace.
//   - name: configured instance name to repoint.
//   - key: resolved credential key that receives the secret.
//   - secret: secret written to the credential store. It never appears in a
//     result or an error.
//
// Returns:
//   - error: a wrapped error when the store rejects the write or the
//     configuration cannot record the reference.
func (a *Credentials) storeCredential(
	ctx context.Context,
	service string,
	name string,
	key string,
	secret string,
) error {
	err := a.store.Set(ctx, service, key, secret)
	if err != nil {
		return fmt.Errorf("write secret to service %q: %w", service, err)
	}

	ref := instance.CredentialRef{Source: instance.KeyringSource, Key: key}

	err = a.local.SetCredential(name, ref)
	if err != nil {
		return fmt.Errorf("record keyring reference: %w", err)
	}

	err = a.local.ClearPassword(name)
	if err != nil {
		return fmt.Errorf("clear legacy password: %w", err)
	}

	return nil
}

// stored reports whether the credential store already holds a key.
//
// A read that fails for any reason other than an absent credential leaves
// presence unknown, so a write refuses to guess whether it would replace an
// existing credential. The read also runs before the write, so a store that
// cannot be read is reported before it is offered a secret.
//
// Parameters:
//   - ctx: context checked before the credential store call.
//   - service: credential store namespace.
//   - key: credential key to read.
//
// Returns:
//   - bool: true when the store already holds the key.
//   - error: a wrapped sentinel error when the store cannot be read.
func (a *Credentials) stored(
	ctx context.Context,
	service string,
	key string,
) (bool, error) {
	_, err := a.store.Get(ctx, service, key)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, credentials.ErrNotFound) {
		return false, nil
	}

	return false, fmt.Errorf("read credential %q in service %q: %w", key, service, err)
}

// isExternalSource reports whether a credential source is owned by another system.
//
// A mounted secret file and an environment variable are read by an external
// system, so agh-cli cannot clear them. A keyring credential, an explicit
// plaintext password, and the unauthenticated source are all agh-cli's to manage,
// and a legacy instance without a credential reference reports the plaintext
// source.
//
// Parameters:
//   - source: effective configured credential source.
//
// Returns:
//   - bool: true when the source is outside the credential store.
func isExternalSource(source instance.CredentialSource) bool {
	switch source {
	case instance.FileSource, instance.EnvSource:
		return true
	default:
		return false
	}
}
