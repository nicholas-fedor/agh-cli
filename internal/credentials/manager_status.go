// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"fmt"
	"slices"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// Presence reports how the configured credential source currently supplies a
// password for one instance.
type Presence uint8

// PasswordStatus reports the configured password state of one named instance.
// It never carries a secret, a value derived from one, or the instance username.
type PasswordStatus struct {
	// Instance is the instance name whose password was inspected.
	Instance string
	// Source is the configured credential source. A legacy instance without a
	// credential reference reports instance.PlaintextSource.
	Source instance.CredentialSource
	// Target names the configured credential identity: a keyring key, a
	// mounted-secret path, or an environment variable name. It is empty for a
	// source that owns no identity, such as plaintext or none.
	Target string
	// TargetKind names the field the configured source reads: "key", "path", or
	// "variable". It is empty when Target is, so command output never confuses a
	// keyring key, a mounted-secret path, and an environment variable name, and
	// the command layer never names a credential source itself.
	TargetKind string
	// Presence reports how the configured source currently supplies a password.
	Presence Presence
	// Err explains why Presence is unknown for a keyring source. Its message
	// never contains a secret. It is nil when the store answered the read.
	Err error
}

// PasswordReport reports credential store state for a service and its named
// instances.
//
// The operating system credential store cannot enumerate its entries, so presence
// is reported per named instance instead of per stored credential.
type PasswordReport struct {
	// Backend is the credential store backend name.
	Backend string
	// Service is the credential store namespace.
	Service string
	// Available reports whether every credential store read succeeded.
	Available bool
	// Instances contains one entry per named instance in configuration order.
	Instances []PasswordStatus
}

const (
	// PresenceUnknown means agh-cli cannot determine presence. An environment
	// variable and a mounted secret file belong to an external system, and a
	// keyring source whose read failed is unknown for the same reason.
	PresenceUnknown Presence = iota
	// PresenceAbsent means the configured source supplies no password.
	PresenceAbsent
	// PresencePresent means the configured source supplies a password.
	PresencePresent
)

// StatusPassword reports credential store state without ever returning a secret.
//
// The operating system credential store cannot enumerate its entries, so presence
// is reported per named instance. A named instance is inspected even when its
// source is not the keyring, because a configuration reference is the only
// description of the credential agh-cli will use for it. The report carries no
// username, because the configured identity is answered by
// [Manager.StatusUsername].
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - names: instance names to inspect, or an empty slice to inspect every
//     configured instance in configuration order.
//
// Returns:
//   - PasswordReport: the backend, the service, and one entry per instance.
//   - error: a wrapped error when a requested name is unknown.
func (m *Manager) StatusPassword(
	ctx context.Context,
	names []string,
) (PasswordReport, error) {
	service := m.service()

	selected, err := m.statusConfigs(names)
	if err != nil {
		return PasswordReport{}, fmt.Errorf("select instances for password status: %w", err)
	}

	result := PasswordReport{
		Backend:   m.store.Backend(),
		Service:   service,
		Available: true,
		Instances: make([]PasswordStatus, 0, len(selected)),
	}

	for _, cfg := range selected {
		result.Instances = append(result.Instances, m.passwordStatus(ctx, service, cfg))
	}

	result.Available = !slices.ContainsFunc(
		result.Instances,
		func(entry PasswordStatus) bool { return entry.Err != nil },
	)

	return result, nil
}

// passwordStatus reports the configured password state of one instance.
//
// Parameters:
//   - ctx: context checked before the credential store call.
//   - service: credential store namespace.
//   - cfg: configured instance whose credential reference is inspected.
//
// Returns:
//   - PasswordStatus: the configured source, its identity, and its presence.
func (m *Manager) passwordStatus(
	ctx context.Context,
	service string,
	cfg instance.Config,
) PasswordStatus {
	source, target := credentialIdentity(cfg)
	entry := PasswordStatus{
		Instance:   cfg.Name,
		Source:     source,
		Target:     target,
		TargetKind: targetKind(source),
		Presence:   PresenceUnknown,
		Err:        nil,
	}

	if source != instance.KeyringSource {
		entry.Presence = externalPresence(source, cfg)

		return entry
	}

	present, err := m.stored(ctx, service, target)
	if err != nil {
		entry.Presence = PresenceUnknown
		entry.Err = err

		return entry
	}

	entry.Presence = PresenceAbsent
	if present {
		entry.Presence = PresencePresent
	}

	return entry
}

// statusConfigs resolves the instances inspected by StatusPassword and
// StatusUsername.
//
// Parameters:
//   - names: requested instance names, or an empty slice for every configured
//     instance.
//
// Returns:
//   - []instance.Config: the inspected configurations in report order.
//   - error: a wrapped [instance.ErrUnknownInstance] for an unknown name.
func (m *Manager) statusConfigs(names []string) ([]instance.Config, error) {
	instances := m.local.Instances()

	if len(names) == 0 {
		configs := make([]instance.Config, 0, len(instances))

		for _, name := range m.local.OrderedNames() {
			configs = append(configs, instances[name])
		}

		return configs, nil
	}

	configs := make([]instance.Config, 0, len(names))

	for _, name := range names {
		cfg, exists := instances[name]
		if !exists {
			return nil, fmt.Errorf("%w: %q", instance.ErrUnknownInstance, name)
		}

		configs = append(configs, cfg)
	}

	return configs, nil
}

// credentialIdentity reports the configured source and its credential identity.
//
// A legacy instance without a credential reference reports the plaintext source and
// no identity. A keyring reference without a key reports the instance name, the
// key every other keyring operation uses for it. A keyring key, a mounted-secret path, and an environment variable
// name are configuration rather than secrets, so status may report them.
//
// Parameters:
//   - cfg: configured instance whose credential reference is inspected.
//
// Returns:
//   - instance.CredentialSource: the effective configured source.
//   - string: the credential identity, or an empty string when the source owns
//     none.
func credentialIdentity(cfg instance.Config) (instance.CredentialSource, string) {
	if cfg.Credential == nil {
		return instance.PlaintextSource, ""
	}

	switch cfg.Credential.Source {
	case instance.KeyringSource:
		return instance.KeyringSource, credentialKeyFor(cfg, "")
	case instance.FileSource:
		return instance.FileSource, cfg.Credential.Path
	case instance.EnvSource:
		return instance.EnvSource, cfg.Credential.Env
	default:
		return cfg.Credential.Source, ""
	}
}

// targetKind names the kind of credential identity a source reads.
//
// Parameters:
//   - source: configured credential source.
//
// Returns:
//   - string: "key", "path", or "variable", or an empty string when the source
//     owns no identity.
func targetKind(source instance.CredentialSource) string {
	switch source {
	case instance.KeyringSource:
		return "key"
	case instance.FileSource:
		return "path"
	case instance.EnvSource:
		return "variable"
	default:
		// The legacy plaintext password and the unauthenticated source own no
		// credential identity, and an unsupported source is reported by its
		// configuration alone.
		return ""
	}
}

// externalPresence reports presence for a source agh-cli does not read.
//
// A legacy plaintext password and the unauthenticated source are decided from the
// configuration alone. An environment variable and a mounted secret file belong to
// an external system, so agh-cli reports unknown rather than reading a secret to
// answer a status question.
//
// Parameters:
//   - source: configured credential source.
//   - cfg: configured instance supplying the legacy password.
//
// Returns:
//   - Presence: the presence reported for the source.
func externalPresence(
	source instance.CredentialSource,
	cfg instance.Config,
) Presence {
	switch source {
	case instance.PlaintextSource:
		if cfg.Password == "" {
			return PresenceAbsent
		}

		return PresencePresent
	case instance.NoneSource:
		return PresenceAbsent
	default:
		return PresenceUnknown
	}
}
