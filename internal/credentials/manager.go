// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"errors"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// Config is the configuration surface required by the credential use cases.
//
// The configuration manager satisfies the interface. The interface is defined
// here, so this package never depends on the configuration package. Narrowing
// the dependency also keeps the manager testable with a fake and keeps it from
// depending on instance mutation or persistence policy it does not own.
type Config interface {
	// CredentialService returns the credential store namespace shared by every
	// instance. It is never empty.
	//
	// Returns:
	//   - string: the credential store namespace.
	CredentialService() string
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
	// ClearLegacyPassword removes the legacy plaintext password of one instance
	// in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	ClearLegacyPassword(name string) error
	// ClearCredential removes the credential reference of one instance in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	ClearCredential(name string) error
	// ClearUsername removes the administrator username of one instance in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	ClearUsername(name string) error
	// SetUsername records the administrator username of one instance in memory.
	//
	// Parameters:
	//   - name: instance identifier to update.
	//   - username: AdGuard Home administrator username.
	//
	// Returns:
	//   - error: a wrapped error when the instance is unknown.
	SetUsername(name, username string) error
	// Save writes the current in-memory configuration to its source file.
	//
	// Returns:
	//   - error: a wrapped error when the configuration cannot be written.
	Save() error
}

// Manager coordinates credential use cases across the operating system
// credential store and the local configuration.
//
// The coordinator owns credential policy. The command layer owns presentation
// and secret input, so every method accepts a secret as an already-read string
// and never reads standard input itself. No result, message, or error returned
// by this type carries a secret or a value derived from one.
type Manager struct {
	// store is the credential store written by set, clear, and migrate.
	store Store
	// local is the configuration supplying the credential service and the
	// instance set.
	local Config
}

// PasswordSetResult reports the outcome of storing one instance password.
//
// The result describes configuration state only. It never carries the secret or a
// value derived from it.
type PasswordSetResult struct {
	// Instance is the instance whose password was written and now referenced.
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

// PasswordClearResult reports the outcome of clearing one instance password or
// every password of the configured service.
//
// The result describes configuration state only. It never carries the secret or a
// value derived from it.
type PasswordClearResult struct {
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
	// Shared reports that the stored credential was kept, because another
	// configured instance still reads its password through the same key.
	Shared bool
	// All reports whether every credential of the service was cleared.
	All bool
	// Saved reports whether the configuration file was rewritten. A false value
	// means the file still references a credential that was already deleted.
	Saved bool
}

// InstancePasswordRemoval reports what happened to the stored password of an
// instance being removed.
//
// The removal describes configuration and store state only. It never carries a
// secret or a value derived from one.
type InstancePasswordRemoval struct {
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

// ErrOrphanedCredential indicates that a credential exists in the store while the
// configuration does not reference it, so no command would ever use it.
//
// The error names the service and key, because an unreferenced entry is
// otherwise invisible: the instance reports the source it is configured for, not
// the entries the store happens to hold.
var ErrOrphanedCredential = errors.New("credential is stored but unreferenced")

// ErrCredentialReplacedUnrecorded indicates that a stored secret was replaced
// while the configuration still describes the previous one.
//
// This is not an orphan: the file on disk references the key, so the instance
// will authenticate with the new secret as though the command had succeeded. The
// change simply is not recorded, which is why the command reports it instead of
// removing the entry.
var ErrCredentialReplacedUnrecorded = errors.New(
	"stored secret was replaced but the configuration is unchanged",
)

// NewManager creates a credential coordinator.
//
// Parameters:
//   - store: credential store backing set, clear, status, and migrate. It must
//     not be nil.
//   - local: configuration supplying the credential service and the instance
//     set. It must not be nil.
//
// Returns:
//   - *Manager: coordinator bound to the supplied dependencies.
func NewManager(store Store, local Config) *Manager {
	return &Manager{store: store, local: local}
}

// ClearAllPasswords removes every credential stored under the configured service.
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
//   - PasswordClearResult: the cleared service.
//   - error: a wrapped error when the store rejects the delete.
func (m *Manager) ClearAllPasswords(ctx context.Context) (PasswordClearResult, error) {
	service := m.service()

	err := m.store.DeleteAll(ctx, service)
	if err != nil {
		return PasswordClearResult{}, fmt.Errorf(
			"delete credentials in service %q: %w",
			service,
			err,
		)
	}

	return PasswordClearResult{Service: service, Removed: true, All: true}, nil
}

// ClearPassword removes the stored credential of one configured instance and detaches the
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
// Removing an instance from the configuration deletes its stored credential, so
// clearing an instance is for detaching a password an operator keeps. Clearing an
// absent credential is not an error, which makes a repeated clear safe. The
// reference removal is idempotent for the same reason, so a repeated clear also
// converges.
//
// A key another configured instance still reads is kept, and only this
// instance's reference is removed, so clearing one instance never breaks
// another.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - name: configured instance name supplying the credential key.
//
// Returns:
//   - PasswordClearResult: the cleared identity, whether a credential was
//     removed or kept for another instance, and whether the configuration was
//     rewritten.
//   - error: a wrapped [ErrExternalCredentialSource] for a file or environment
//     instance, a wrapped [instance.ErrUnknownInstance] for an unknown name, or a
//     wrapped error when the store rejects the read or the delete, or the
//     configuration cannot be written.
func (m *Manager) ClearPassword(
	ctx context.Context,
	name string,
) (PasswordClearResult, error) {
	cfg, exists := m.local.Instances()[name]
	if !exists {
		return PasswordClearResult{}, fmt.Errorf("%w: %q", instance.ErrUnknownInstance, name)
	}

	source, _ := credentialIdentity(cfg)
	if isExternalSource(source) {
		return PasswordClearResult{}, fmt.Errorf(
			"clear credential of %q: %w: source is %q",
			name,
			ErrExternalCredentialSource,
			source,
		)
	}

	service := m.service()
	credentialKey := credentialKeyFor(cfg, "")

	result := PasswordClearResult{Instance: name, Service: service, Key: credentialKey}

	if otherInstanceReferencesKey(m.local.Instances(), name, credentialKey) {
		result.Shared = true
	} else {
		removed, err := deleteStoredCredential(ctx, m.store, service, credentialKey)
		if err != nil {
			return result, fmt.Errorf("clear credential %q: %w", credentialKey, err)
		}

		result.Removed = removed
	}

	err := m.local.ClearCredential(name)
	if err != nil {
		return result, fmt.Errorf("remove credential reference of %q: %w", name, err)
	}

	result.Saved, err = m.save()
	if err != nil {
		return result, fmt.Errorf("clear credential %q: %w", credentialKey, err)
	}

	return result, nil
}

// RemoveInstancePassword deletes the stored password of an instance that is
// being removed from the configuration.
//
// The credential is reached through the configuration, not through the instance
// name, so only an entry the instance declared is deleted. An instance whose
// source resolves outside the credential store leaves the store untouched, so a
// host with no usable store can still remove it. A key another configured
// instance still reads is kept, so removing one instance never breaks another.
//
// An unknown instance owns no credential, so the store is left alone and the
// caller's removal reports the unknown name. An instance whose stanza could not
// be decoded declares no credential either.
//
// The configuration is not changed. The caller removes the instance and saves
// the file after this call succeeds, so a failed delete keeps the instance and
// no secret is left behind without the reference that made it reachable.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - name: configured instance being removed.
//
// Returns:
//   - InstancePasswordRemoval: the credential identity and whether an entry was
//     deleted or kept.
//   - error: a wrapped error when the store cannot be read or the delete fails.
func (m *Manager) RemoveInstancePassword(
	ctx context.Context,
	name string,
) (InstancePasswordRemoval, error) {
	removal := InstancePasswordRemoval{Service: m.service(), Key: "", Removed: false, Shared: false}

	cfg, exists := m.local.Instances()[name]
	if !exists {
		return removal, nil
	}

	key, stored := keyringCredentialKey(cfg)
	if !stored {
		return removal, nil
	}

	removal.Key = key

	if otherInstanceReferencesKey(m.local.Instances(), name, key) {
		removal.Shared = true

		return removal, nil
	}

	removed, err := deleteStoredCredential(ctx, m.store, removal.Service, key)
	if err != nil {
		return removal, fmt.Errorf(
			"delete credential %q in service %q: %w",
			key,
			removal.Service,
			err,
		)
	}

	removal.Removed = removed

	return removal, nil
}

// SetPassword stores one instance password in the operating system credential
// store and points the configured instance at it.
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
// The configured username is left untouched, because a username is configuration
// and a password is a secret, and the two are managed independently.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - name: configured instance name supplying the default credential key.
//   - key: credential key, or an empty string to use the configured key.
//   - secret: secret read by the command layer. It never appears in a result or
//     an error.
//
// Returns:
//   - PasswordSetResult: the written identity, whether it replaced a credential,
//     and whether the configuration was rewritten.
//   - error: a wrapped error when the instance is unknown, the store rejects the
//     read or the write, or the configuration cannot be written.
func (m *Manager) SetPassword(
	ctx context.Context,
	name string,
	key string,
	secret string,
) (PasswordSetResult, error) {
	service := m.service()

	credentialKey, err := m.credentialKey(name, key)
	if err != nil {
		return PasswordSetResult{}, fmt.Errorf("resolve credential key for %q: %w", name, err)
	}

	// Captured before the write, because storeCredential replaces the reference
	// and the rollback needs to know what the configuration said on disk.
	previous := credentialReference(m.local.Instances()[name])

	replaced, err := m.stored(ctx, service, credentialKey)
	if err != nil {
		return PasswordSetResult{}, fmt.Errorf("check credential %q: %w", credentialKey, err)
	}

	err = m.storeCredential(ctx, service, name, credentialKey, secret)
	if err != nil {
		return PasswordSetResult{}, fmt.Errorf("set credential %q: %w", credentialKey, err)
	}

	result := PasswordSetResult{
		Instance: name,
		Backend:  m.store.Backend(),
		Service:  service,
		Key:      credentialKey,
		Replaced: replaced,
	}

	result.Saved, err = m.save()
	if err != nil {
		return result, fmt.Errorf(
			"set credential %q: %w",
			result.Key,
			m.rollbackCredential(ctx, service, result, previous, err),
		)
	}

	return result, nil
}

// credentialReference copies the credential reference of one instance.
//
// The copy is taken before a write replaces the reference, so the pre-write
// state survives the mutation it describes.
//
// Parameters:
//   - cfg: configured instance whose reference is copied.
//
// Returns:
//   - *instance.CredentialRef: an independent copy, or nil when the instance has
//     no reference.
func credentialReference(cfg instance.Config) *instance.CredentialRef {
	if cfg.Credential == nil {
		return nil
	}

	copied := *cfg.Credential

	return &copied
}

// referencesKey reports whether a configuration reference points at one
// credential key through the keyring.
//
// This is what decides whether a stored entry is reachable. A credential source
// other than the keyring resolves its secret elsewhere, so a reference to it
// never reaches a store entry.
//
// Parameters:
//   - ref: configuration reference, or nil when the instance has none.
//   - key: credential key to test for.
//
// Returns:
//   - bool: true when the reference resolves key through the keyring.
func referencesKey(ref *instance.CredentialRef, key string) bool {
	return ref != nil && ref.Source == instance.KeyringSource && ref.Key == key
}

// credentialKey resolves the credential key written for one configured instance.
//
// Parameters:
//   - name: configured instance name.
//   - key: explicit credential key, or an empty string.
//
// Returns:
//   - string: the credential key.
//   - error: a wrapped [instance.ErrUnknownInstance] when the instance is unknown.
func (m *Manager) credentialKey(name, key string) (string, error) {
	cfg, exists := m.local.Instances()[name]
	if !exists {
		return "", fmt.Errorf("%w: %q", instance.ErrUnknownInstance, name)
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
//   - store: credential store holding the entry.
//   - service: credential store namespace.
//   - key: credential key to remove.
//
// Returns:
//   - bool: true when an entry was deleted.
//   - error: a wrapped error when the store cannot be read or the delete fails.
func deleteStoredCredential(
	ctx context.Context,
	store Store,
	service string,
	key string,
) (bool, error) {
	_, err := store.Get(ctx, service, key)
	if errors.Is(err, ErrNotFound) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("read store: %w", err)
	}

	err = store.Delete(ctx, service, key)
	if err != nil {
		return false, fmt.Errorf("delete store entry: %w", err)
	}

	return true, nil
}

// keyringCredentialKey returns the credential store key one instance reads its
// password through.
//
// Only a keyring reference names an entry agh-cli owns, so every other source
// reports false. An empty configured key resolves to the instance name, which
// matches the keyring key default applied by instance validation and is applied
// here because a configuration manager holds the raw document.
//
// Parameters:
//   - cfg: configured instance whose credential reference is resolved.
//
// Returns:
//   - string: the credential key the instance reads its password through.
//   - bool: true when the instance reads its password from the credential store.
func keyringCredentialKey(cfg instance.Config) (string, bool) {
	if cfg.Credential == nil || cfg.Credential.Source != instance.KeyringSource {
		return "", false
	}

	return credentialKeyFor(cfg, ""), true
}

// otherInstanceReferencesKey reports whether a credential key is referenced by
// any instance other than the one being written.
//
// A key is not exclusive to an instance, so removing the entry a use case wrote
// would destroy another instance's working password. The instance being written
// is excluded because the store write has already attached the key to it in
// memory, so it would always match and mask the real answer.
//
// Parameters:
//   - instances: configured instances searched for the key.
//   - exclude: instance name to leave out of the search.
//   - key: credential key to look for.
//
// Returns:
//   - bool: true when another configured instance references the key.
func otherInstanceReferencesKey(
	instances map[string]instance.Config,
	exclude string,
	key string,
) bool {
	for name, cfg := range instances {
		if name == exclude {
			continue
		}

		otherKey, resolves := keyringCredentialKey(cfg)
		if resolves && otherKey == key {
			return true
		}
	}

	return false
}

// rollbackCredential undoes a credential store write whose configuration write
// failed.
//
// The configuration is written after the store precisely so a failed store write
// leaves the instance unchanged. The reverse failure, a store write that
// succeeds and a configuration write that does not, would otherwise leave a
// secret nothing references, and no command reports an unreferenced entry.
//
// A newly created entry is deleted, which restores the state before the command
// ran. An entry the configuration already referenced is not deleted: the file on
// disk still points at that key, so removing the entry would leave a live
// reference to nothing. That case is reported instead, naming the instance and
// the key so the operator can re-run the command to record the change.
//
// The orphan test is the configuration, not the store. Whether an entry existed
// before the write says nothing about whether the configuration points at it: a
// key can be present in the store while the instance references another key, and
// a referenced key can be absent from the store. Only the reference decides
// whether the entry is reachable.
//
// Parameters:
//   - ctx: context governing the compensating store call.
//   - service: credential store namespace that was written.
//   - written: the result of the store write, which records the key and the
//     instance.
//   - previous: the credential reference the configuration held before the write,
//     or nil when the instance had none.
//   - saveErr: the configuration write failure that triggered the rollback.
//
// Returns:
//   - error: the configuration failure, joined with the rollback outcome.
func (m *Manager) rollbackCredential(
	ctx context.Context,
	service string,
	written PasswordSetResult,
	previous *instance.CredentialRef,
	saveErr error,
) error {
	saveFailure := fmt.Errorf("write config %q: %w", written.Instance, saveErr)

	if referencesKey(previous, written.Key) ||
		otherInstanceReferencesKey(m.local.Instances(), written.Instance, written.Key) {
		return errors.Join(
			saveFailure,
			fmt.Errorf(
				"%w: key %q in service %q",
				ErrCredentialReplacedUnrecorded,
				written.Key,
				service,
			),
		)
	}

	deleteErr := m.store.Delete(ctx, service, written.Key)
	if deleteErr != nil {
		return errors.Join(
			saveFailure,
			fmt.Errorf(
				"%w: key %q in service %q is stored but no configured instance "+
					"references it, and it could not be removed automatically",
				ErrOrphanedCredential,
				written.Key,
				service,
			),
			fmt.Errorf("remove rolled back credential %q: %w", written.Key, deleteErr),
		)
	}

	return fmt.Errorf(
		"write config %q: %w; the credential written for key %q was removed again",
		written.Instance,
		saveErr,
		written.Key,
	)
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
func (m *Manager) save() (bool, error) {
	err := m.local.Save()
	if err != nil {
		return false, fmt.Errorf("save credential configuration: %w", err)
	}

	return true, nil
}

// service returns the credential store namespace used by every use case.
//
// Returns:
//   - string: the credential store namespace.
func (m *Manager) service() string {
	return m.local.CredentialService()
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
func (m *Manager) storeCredential(
	ctx context.Context,
	service string,
	name string,
	key string,
	secret string,
) error {
	err := m.store.Set(ctx, service, key, secret)
	if err != nil {
		return fmt.Errorf("write secret to service %q: %w", service, err)
	}

	ref := instance.CredentialRef{Source: instance.KeyringSource, Key: key}

	err = m.local.SetCredential(name, ref)
	if err != nil {
		return fmt.Errorf("record keyring reference: %w", err)
	}

	err = m.local.ClearLegacyPassword(name)
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
func (m *Manager) stored(
	ctx context.Context,
	service string,
	key string,
) (bool, error) {
	_, err := m.store.Get(ctx, service, key)
	if err == nil {
		return true, nil
	}

	if errors.Is(err, ErrNotFound) {
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
