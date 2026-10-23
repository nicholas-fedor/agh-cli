// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"strings"

	"go.yaml.in/yaml/v4"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// CredentialsSettings holds the top-level credential store configuration.
type CredentialsSettings struct {
	// Service is the credential store service namespace shared by every
	// instance. A manager never reports an empty service.
	Service string `yaml:"service"`
}

// credentialField pairs one credential stanza key with its configured value.
type credentialField struct {
	// name is the raw configuration field name.
	name string
	// value is the field value configured for the instance.
	value string
}

// DefaultCredentialService is the credential store service namespace applied
// when the configuration omits credentials.service.
const DefaultCredentialService = "agh-cli"

// configFileMode is the permission mode of every written configuration file.
const configFileMode = 0o600

// configDirMode is the permission mode of a configuration directory created by
// a save. The XDG base directory specification requires user-owned data
// directories to be private, and the configuration may name a mounted secret
// path, so the directory never exposes the configuration to other users.
const configDirMode = 0o700

// tempFilePattern is the [os.CreateTemp] pattern suffix of an in-progress
// write.
const tempFilePattern = ".tmp-*"

// credentialsFieldName is the top-level key holding the credential settings.
const credentialsFieldName = "credentials"

// instancesFieldName is the top-level key holding the configured instances.
const instancesFieldName = "instances"

// serviceFieldName is the credentials key holding the service namespace.
const serviceFieldName = "service"

// hostFieldName is the instance key holding the AdGuard Home host.
const hostFieldName = "host"

// schemeFieldName is the instance key holding the transport scheme.
const schemeFieldName = "scheme"

// usernameFieldName is the instance key holding the administrator username.
const usernameFieldName = "username"

// passwordFieldName is the instance key holding the legacy plaintext password.
const passwordFieldName = "password"

// credentialFieldName is the instance key holding the credential stanza.
const credentialFieldName = "credential"

// sourceFieldName is the credential stanza key holding the source.
const sourceFieldName = "source"

// keyFieldName is the credential stanza key holding the keyring key.
const keyFieldName = "key"

// pathFieldName is the credential stanza key holding the mounted-secret path.
const pathFieldName = "path"

// envFieldName is the credential stanza key holding the variable name.
const envFieldName = "env"

// ClearCredential removes the credential reference of one instance in memory.
//
// ClearCredential keeps the host, scheme, username, and password of the
// instance, so only the credential stanza disappears. After a save the instance
// serializes as a legacy instance without a stanza, which means a cleared
// instance writes its plaintext password again. Clearing an instance that has
// no credential reference is a no-op, so repeating the call is safe.
//
// Parameters:
//   - name: instance identifier to update.
//
// Returns:
//   - error: ErrInstanceNotFound when name is not configured, or a wrapped
//     [instance.ErrInvalidConfig] when its stanza could not be decoded.
func (m *Manager) ClearCredential(name string) error {
	cfg, err := m.editableInstance(name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	cfg.Credential = nil
	m.data.Instances[name] = cfg

	return nil
}

// ClearLegacyPassword removes the legacy plaintext password of one instance in
// memory.
//
// The field belongs to the legacy model, where a username and a plaintext
// password were both written when the instance was added. It survives only for
// instances that never adopted a credential source, so this mutator exists to
// drop it during a migration rather than as a way to unset an instance's
// password. Use [Manager.ClearCredential] to drop a credential reference.
//
// ClearLegacyPassword does not change the credential reference of the instance, so
// migrating an instance to a credential source and dropping its legacy plaintext
// password stay two independent steps.
//
// Parameters:
//   - name: instance identifier to update.
//
// Returns:
//   - error: ErrInstanceNotFound when name is not configured, or a wrapped
//     [instance.ErrInvalidConfig] when its stanza could not be decoded.
func (m *Manager) ClearLegacyPassword(name string) error {
	cfg, err := m.editableInstance(name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	cfg.Password = ""
	m.data.Instances[name] = cfg

	return nil
}

// ClearUsername removes the administrator username of one instance in memory.
//
// The change is limited to the username. A stored credential reference and a
// plaintext password both survive, so clearing a username never detaches an
// instance from its credential source. Clearing an instance that has no
// username is a no-op, so repeating the call is safe.
//
// Parameters:
//   - name: instance identifier to update.
//
// Returns:
//   - error: a wrapped [instance.ErrUnknownInstance] when name is not
//     configured, or a wrapped [instance.ErrInvalidConfig] when its stanza could
//     not be decoded.
func (m *Manager) ClearUsername(name string) error {
	cfg, err := m.usernameInstance(name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	cfg.Username = ""
	m.data.Instances[name] = cfg

	return nil
}

// SetUsername records the AdGuard Home administrator username of one instance in
// memory. It does not write the change to disk.
//
// The username is configuration rather than a secret, so it is stored in the
// configuration file and never in the credential store. The change is
// independent of the stored password, so setting a username leaves a stored
// credential untouched.
//
// Parameters:
//   - name: instance identifier to update.
//   - username: AdGuard Home administrator username.
//
// Returns:
//   - error: a wrapped [instance.ErrUnknownInstance] when name is not
//     configured, or a wrapped [instance.ErrInvalidConfig] when its stanza could
//     not be decoded.
func (m *Manager) SetUsername(name, username string) error {
	cfg, err := m.usernameInstance(name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	cfg.Username = username
	m.data.Instances[name] = cfg

	return nil
}

// usernameInstance returns the configuration of one instance whose username
// changes.
//
// The username commands report an unknown instance with the instance domain's
// sentinel, as every other credential command does. A stanza that could not be
// decoded still reports its decoding failure.
//
// Parameters:
//   - name: instance identifier to look up.
//
// Returns:
//   - instance.Config: the decoded configuration.
//   - error: a wrapped [instance.ErrUnknownInstance] when name is not
//     configured, or a wrapped [instance.ErrInvalidConfig] when its stanza could
//     not be decoded.
func (m *Manager) usernameInstance(name string) (instance.Config, error) {
	cfg, err := m.editableInstance(name)
	if errors.Is(err, ErrInstanceNotFound) {
		return instance.Config{}, fmt.Errorf("%w: %q", instance.ErrUnknownInstance, name)
	}

	if err != nil {
		return instance.Config{}, fmt.Errorf("%w", err)
	}

	return cfg, nil
}

// Credentials returns a snapshot of the top-level credential settings.
//
// The service is never empty. A configuration without a credentials mapping
// reports DefaultCredentialService.
//
// Returns:
//   - CredentialsSettings: effective credential store settings.
func (m *Manager) Credentials() CredentialsSettings {
	return m.data.Credentials
}

// CredentialService returns the credential store namespace shared by every
// instance.
//
// The service is never empty. A configuration without a credentials mapping
// reports DefaultCredentialService.
//
// Returns:
//   - string: the credential store namespace.
func (m *Manager) CredentialService() string {
	if m.data.Credentials.Service == "" {
		return DefaultCredentialService
	}

	return m.data.Credentials.Service
}

// SetCredential records the credential reference of one instance in memory.
//
// SetCredential stores a copy of ref without validating it, because credential
// policy belongs to the resolver. It leaves an existing password in place;
// [Manager.Save] keeps writing that password only for instance.PlaintextSource
// and for an instance without a reference.
//
// Parameters:
//   - name: instance identifier to update.
//   - ref: credential reference to store.
//
// Returns:
//   - error: ErrInstanceNotFound when name is not configured, or a wrapped
//     [instance.ErrInvalidConfig] when its stanza could not be decoded.
func (m *Manager) SetCredential(name string, ref instance.CredentialRef) error {
	cfg, err := m.editableInstance(name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	stored := ref

	cfg.Credential = &stored
	m.data.Instances[name] = cfg

	return nil
}

// loadCredentials replaces the manager's credential settings from a YAML
// credentials mapping.
//
// An absent mapping keeps the default service and records that the source file
// declares no credentials mapping, so Save does not add one. An empty service
// also keeps the default, because the service namespace must never be empty.
//
// Parameters:
//   - node: YAML value for the top-level credentials key.
//
// Returns:
//   - error: ErrInvalidCredentialsMap when the value is not a complete mapping,
//     or a wrapped error when the service value is not a string.
func (m *Manager) loadCredentials(node *yaml.Node) error {
	if isZeroNode(node) {
		m.data.Credentials = CredentialsSettings{Service: DefaultCredentialService}
		m.credentialsSet = false

		return nil
	}

	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return ErrInvalidCredentialsMap
	}

	service, err := decodeCredentialService(mappingValue(node, serviceFieldName))
	if err != nil {
		return fmt.Errorf("load credential service: %w", err)
	}

	m.data.Credentials = CredentialsSettings{Service: service}
	m.credentialsSet = true

	return nil
}

// decodeCredentialService decodes a credentials.service value.
//
// An absent or empty value keeps DefaultCredentialService, because the service
// namespace must never be empty.
//
// Parameters:
//   - node: YAML value of the service key, or nil when the key is absent.
//
// Returns:
//   - string: the configured service namespace.
//   - error: a wrapped error when the value is not a string.
func decodeCredentialService(node *yaml.Node) (string, error) {
	if node == nil {
		return DefaultCredentialService, nil
	}

	var service string

	err := node.Decode(&service)
	if err != nil {
		return "", fmt.Errorf("decode service value: %w", err)
	}

	if service == "" {
		return DefaultCredentialService, nil
	}

	return service, nil
}

// writeCredentials appends the top-level credentials mapping.
//
// Parameters:
//   - builder: destination for the formatted lines.
//   - settings: credential store settings to serialize.
//
// Returns:
//   - error: a wrapped error when a line cannot be written.
func writeCredentials(builder *strings.Builder, settings CredentialsSettings) error {
	err := writeBuilderLine(builder, "%s:\n", credentialsFieldName)
	if err != nil {
		return fmt.Errorf("write credentials key: %w", err)
	}

	err = writeBuilderLine(builder, "  %s: %s\n", serviceFieldName, settings.Service)
	if err != nil {
		return fmt.Errorf("write credential service: %w", err)
	}

	return nil
}

// writeCredentialStanza appends one instance's credential reference.
//
// The stanza always leads with source, and the remaining fields follow in the
// fixed order key, path, env. Empty fields are omitted, so one reference always
// serializes identically.
//
// The keys agh-cli does not read follow the fields it owns, as they were read.
//
// Parameters:
//   - builder: destination for the credential fields.
//   - ref: credential reference to serialize.
//   - unknown: entries of the credential stanza agh-cli does not read.
//
// Returns:
//   - error: a wrapped error when a field cannot be written.
func writeCredentialStanza(
	builder *strings.Builder,
	ref *instance.CredentialRef,
	unknown []configField,
) error {
	err := writeInstanceLine(builder, "    %s:\n", credentialFieldName)
	if err != nil {
		return fmt.Errorf("write credential key: %w", err)
	}

	fields := []credentialField{
		{name: sourceFieldName, value: string(ref.Source)},
		{name: keyFieldName, value: ref.Key},
		{name: pathFieldName, value: ref.Path},
		{name: envFieldName, value: ref.Env},
	}

	for _, field := range fields {
		if field.value == "" {
			continue
		}

		err = writeInstanceLine(builder, "      %s: %s\n", field.name, field.value)
		if err != nil {
			return fmt.Errorf("write credential field %q: %w", field.name, err)
		}
	}

	err = writeIndentedFields(builder, unknown, credentialFieldIndent)
	if err != nil {
		return fmt.Errorf("write unknown credential fields: %w", err)
	}

	return nil
}
