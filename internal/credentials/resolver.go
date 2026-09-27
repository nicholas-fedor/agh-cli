// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"context"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// Resolver resolves the credential of an instance from its configured source.
//
// Resolution is deterministic. A configuration without a credential reference
// keeps its legacy plaintext password, an explicit keyring, file, or
// environment source is the only source that is read, an unreadable credential
// is an error rather than a fallback, and the none source clears the password
// without any lookup at all.
type Resolver struct {
	// service is the credential store namespace used by instance.KeyringSource.
	service string
	// store is the credential store read by instance.KeyringSource.
	store Store
	// files reads the mounted secret read by instance.FileSource.
	files FileReader
	// env reads the environment variable read by instance.EnvSource.
	env EnvReader
}

// Resolver satisfies the instance credential contract.
var _ instance.CredentialResolver = (*Resolver)(nil)

// NewResolver creates a credential resolver.
//
// Parameters:
//   - service: credential store namespace, or an empty string for
//     [DefaultService].
//   - store: credential store read by instance.KeyringSource. It must not be
//     nil.
//   - files: reader read by instance.FileSource. It must not be nil.
//   - env: reader used by instance.EnvSource. It must not be nil.
//
// Returns:
//   - *Resolver: resolver for the supported credential sources.
func NewResolver(
	service string,
	store Store,
	files FileReader,
	env EnvReader,
) *Resolver {
	if service == "" {
		service = DefaultService
	}

	return &Resolver{
		service: service,
		store:   store,
		files:   files,
		env:     env,
	}
}

// Resolve returns a copy of cfg whose password comes from the configured source.
//
// A configuration without a credential reference is returned unchanged, so a
// legacy plaintext password keeps working. A failed resolution returns cfg
// unchanged alongside the error, because a partially resolved password must
// never reach an AdGuard Home request.
//
// Parameters:
//   - ctx: context governing credential resolution.
//   - cfg: validated instance configuration whose credential source is read.
//
// Returns:
//   - Config: a copy of cfg carrying the resolved password.
//   - error: a wrapped sentinel error when the configured source cannot be read.
func (r *Resolver) Resolve(
	ctx context.Context,
	cfg instance.Config,
) (instance.Config, error) {
	if cfg.Credential == nil {
		return cfg, nil
	}

	password, err := r.resolvePassword(ctx, cfg, *cfg.Credential)
	if err != nil {
		return cfg, fmt.Errorf("resolve credential for instance %q: %w", cfg.Name, err)
	}

	cfg.Password = password

	return cfg, nil
}

// envPassword reads the password from the configured environment variable.
//
// Parameters:
//   - ref: credential reference naming the environment variable.
//
// Returns:
//   - string: the variable value.
//   - error: instance.ErrInvalidCredentialEnv when no variable is configured, or
//     ErrEnvUnset when the configured variable is not set.
func (r *Resolver) envPassword(ref instance.CredentialRef) (string, error) {
	if ref.Env == "" {
		return "", fmt.Errorf("%w: no variable configured", instance.ErrInvalidCredentialEnv)
	}

	password, ok := r.env.Lookup(ref.Env)
	if !ok {
		return "", fmt.Errorf("%w: %q", ErrEnvUnset, ref.Env)
	}

	return password, nil
}

// filePassword reads the password from the configured mounted secret file.
//
// The file bytes become the password exactly as stored, so an external system
// that writes a trailing newline produces a password with that newline.
//
// Parameters:
//   - ctx: context governing the file read.
//   - ref: credential reference naming the mounted secret file.
//
// Returns:
//   - string: the exact file contents.
//   - error: a wrapped file source error when the file cannot be read.
func (r *Resolver) filePassword(
	ctx context.Context,
	ref instance.CredentialRef,
) (string, error) {
	data, err := r.files.Read(ctx, ref.Path)
	if err != nil {
		return "", fmt.Errorf("read mounted credential file: %w", err)
	}

	return string(data), nil
}

// keyringPassword reads the password from the operating system credential store.
//
// An empty key falls back to the instance name, matching the keyring default of
// the instance configuration. The key must not embed a host, so a host change
// never requires re-entering a password.
//
// Parameters:
//   - ctx: context governing the credential store read.
//   - cfg: instance configuration supplying the keyring key default.
//   - ref: credential reference naming the credential key.
//
// Returns:
//   - string: the stored secret.
//   - error: a wrapped credential store error when the credential is absent or
//     the store is unusable.
func (r *Resolver) keyringPassword(
	ctx context.Context,
	cfg instance.Config,
	ref instance.CredentialRef,
) (string, error) {
	key := ref.Key
	if key == "" {
		key = cfg.Name
	}

	password, err := r.store.Get(ctx, r.service, key)
	if err != nil {
		return "", fmt.Errorf(
			"read keyring credential %q from service %q: %w",
			key,
			r.service,
			err,
		)
	}

	return password, nil
}

// resolvePassword reads the password from the configured credential source.
//
// Parameters:
//   - ctx: context governing credential resolution.
//   - cfg: instance configuration supplying the plaintext password and the
//     keyring key default.
//   - ref: credential reference naming the configured source.
//
// Returns:
//   - string: the resolved password, which is empty for instance.NoneSource.
//   - error: instance.ErrInvalidCredentialSource for an unknown source, or a
//     wrapped source error when the configured source cannot be read.
func (r *Resolver) resolvePassword(
	ctx context.Context,
	cfg instance.Config,
	ref instance.CredentialRef,
) (string, error) {
	switch ref.Source {
	case instance.KeyringSource:
		password, err := r.keyringPassword(ctx, cfg, ref)
		if err != nil {
			return "", fmt.Errorf("source %q: %w", ref.Source, err)
		}

		return password, nil
	case instance.FileSource:
		password, err := r.filePassword(ctx, ref)
		if err != nil {
			return "", fmt.Errorf("source %q: %w", ref.Source, err)
		}

		return password, nil
	case instance.EnvSource:
		password, err := r.envPassword(ref)
		if err != nil {
			return "", fmt.Errorf("source %q: %w", ref.Source, err)
		}

		return password, nil
	case instance.PlaintextSource:
		return cfg.Password, nil
	case instance.NoneSource:
		return "", nil
	default:
		return "", fmt.Errorf("%w: %q", instance.ErrInvalidCredentialSource, ref.Source)
	}
}
