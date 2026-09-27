// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"context"
	"errors"
	"fmt"
	"path"
)

// ID is the stable, case-sensitive catalog identity derived from a Config name.
type ID string

// Config contains the connection settings for one AdGuard Home instance.
type Config struct {
	// Name is the stable, case-sensitive identifier used for catalog selection.
	Name string
	// Host is the required AdGuard Home hostname or IP address.
	Host string
	// Scheme is the URL scheme used to contact the instance. Validate normalizes
	// an empty value to HTTPS.
	Scheme string
	// Username is the optional AdGuard Home administrator username.
	Username string
	// Password is the optional AdGuard Home administrator password.
	Password string
	// Credential is the optional credential reference. A nil reference selects
	// the legacy plaintext password only.
	Credential *CredentialRef
}

// CredentialSource identifies where an instance password is read from.
//
// Use KeyringSource, FileSource, EnvSource, PlaintextSource, or NoneSource. A
// configured source is never replaced by another source.
type CredentialSource string

// CredentialRef is the configured location of an instance password.
//
// Only the field consumed by Source is meaningful. Validate rejects a reference
// that populates a field its source ignores.
type CredentialRef struct {
	// Source selects the credential source for the instance.
	Source CredentialSource
	// Key is the stable keyring credential identity. Validate defaults an empty
	// keyring key to the instance name.
	Key string
	// Path is the absolute path of a read-only mounted secret file.
	Path string
	// Env is the name of the environment variable holding the password.
	Env string
}

// CredentialResolver resolves an instance password from its configured
// credential source.
//
// Implementations own credential policy. They decide how keyring, file,
// environment, plaintext, and unauthenticated sources are served, and they
// never return a secret the configuration did not provide.
type CredentialResolver interface {
	// Resolve returns a copy of cfg whose password reflects the configured
	// credential source.
	//
	// Parameters:
	//   - ctx: context governing credential resolution.
	//   - cfg: validated instance configuration whose credential source is read.
	//
	// Returns:
	//   - Config: configuration carrying the resolved password.
	//   - error: a wrapped error when the configured source cannot be resolved.
	Resolve(ctx context.Context, cfg Config) (Config, error)
}

// credentialField pairs a credential reference field name with its configured
// value.
type credentialField struct {
	// name is the raw configuration field name.
	name string
	// value is the field value configured for the instance.
	value string
}

// defaultScheme is used when a configuration omits its transport scheme.
const defaultScheme = "https"

// Supported credential sources.
const (
	// KeyringSource reads the password from the operating system credential store.
	KeyringSource CredentialSource = "keyring"
	// FileSource reads the password from a read-only mounted secret file.
	FileSource CredentialSource = "file"
	// EnvSource reads the password from an environment variable.
	EnvSource CredentialSource = "env"
	// PlaintextSource uses the legacy configuration password field.
	PlaintextSource CredentialSource = "plaintext"
	// NoneSource sends no authentication.
	NoneSource CredentialSource = "none"
)

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

var (
	// ErrInvalidConfig indicates that an instance configuration is invalid.
	ErrInvalidConfig = errors.New("invalid instance configuration")
	// ErrMissingHost indicates that an instance has no configured host.
	ErrMissingHost = errors.New("instance has no host configured")
	// ErrMissingName indicates that an instance has no mapping-derived name.
	ErrMissingName = errors.New("instance has no name")
	// ErrInvalidCredentialSource indicates an unsupported credential source.
	ErrInvalidCredentialSource = errors.New("invalid credential source")
	// ErrInvalidCredentialPath indicates an unusable mounted-secret path.
	ErrInvalidCredentialPath = errors.New("invalid credential path")
	// ErrInvalidCredentialEnv indicates a missing environment variable name.
	ErrInvalidCredentialEnv = errors.New("invalid credential environment variable")
	// ErrUnusedCredentialField indicates a field the configured source ignores.
	ErrUnusedCredentialField = errors.New(
		"credential field is not used by the configured source",
	)
	// ErrMissingPassword indicates a plaintext source without a password.
	ErrMissingPassword = errors.New("instance has no password configured")
)

// credentialSourceFields maps each supported source to the single credential
// reference field it consumes. Sources mapped to an empty field name, such as
// PlaintextSource and NoneSource, consume no reference field.
var credentialSourceFields = map[CredentialSource]string{
	KeyringSource:   keyFieldName,
	FileSource:      pathFieldName,
	EnvSource:       envFieldName,
	PlaintextSource: "",
	NoneSource:      "",
}

// Identity returns the stable, case-sensitive catalog identity derived from Name.
//
// Returns:
//   - ID: Name converted to an instance identity.
func (cfg Config) Identity() ID {
	return ID(cfg.Name)
}

// ConfigFromMap converts a raw instance mapping into a validated Config.
//
// The mapping key supplies Name and is never read from the raw configuration.
// Missing or non-string values become empty strings, and an empty Scheme is
// normalized to HTTPS. A credential stanza of another type is rejected instead
// of ignored, so a mistyped stanza cannot silently fall back to the plaintext
// password.
//
// Parameters:
//   - name: instance name derived from the mapping key.
//   - raw: raw instance settings to decode.
//
// Returns:
//   - Config: validated instance configuration.
//   - error: wrapped validation error when a required field is missing or the
//     credential reference is invalid.
func ConfigFromMap(name string, raw map[string]any) (Config, error) {
	cfg := Config{
		Name:       name,
		Host:       stringValue(raw, "host"),
		Scheme:     stringValue(raw, "scheme"),
		Username:   stringValue(raw, "username"),
		Password:   stringValue(raw, "password"),
		Credential: nil,
	}

	stanza, hasCredential := raw[credentialFieldName]
	if hasCredential {
		credential, err := credentialFromMap(stanza)
		if err != nil {
			return Config{}, fmt.Errorf("validate instance %q: %w", name, err)
		}

		cfg.Credential = credential
	}

	validated, err := cfg.Validate()
	if err != nil {
		return Config{}, fmt.Errorf("validate instance %q: %w", name, err)
	}

	return validated, nil
}

// Validate checks required fields and normalizes the transport scheme and
// credential reference.
//
// Validate requires Name and Host but does not otherwise validate their format.
// A nil credential reference stays nil, and a supplied reference is validated
// strictly: the source must be supported, every populated field must be consumed
// by that source, and an empty keyring key defaults to Name.
//
// Parameters:
//   - cfg: instance configuration to validate.
//
// Returns:
//   - Config: a copy with an empty Scheme normalized to HTTPS and a normalized
//     credential reference, or the zero Config when validation fails.
//   - error: ErrMissingName, ErrMissingHost, or a wrapped credential error.
func (cfg Config) Validate() (Config, error) {
	if cfg.Name == "" {
		return Config{}, ErrMissingName
	}

	if cfg.Host == "" {
		return Config{}, fmt.Errorf("%w: %q", ErrMissingHost, cfg.Name)
	}

	if cfg.Scheme == "" {
		cfg.Scheme = defaultScheme
	}

	if cfg.Credential == nil {
		return cfg, nil
	}

	// The copy keeps the caller's reference untouched while it is normalized.
	credential := *cfg.Credential

	err := credential.validate(cfg.Name, cfg.Password)
	if err != nil {
		return Config{}, fmt.Errorf("instance %q credential: %w", cfg.Name, err)
	}

	cfg.Credential = &credential

	return cfg, nil
}

// credentialFromMap decodes one raw credential stanza.
//
// Parameters:
//   - value: raw credential stanza.
//
// Returns:
//   - *CredentialRef: the decoded reference.
//   - error: ErrInvalidConfig when the stanza is not a mapping.
func credentialFromMap(value any) (*CredentialRef, error) {
	stanza, isMapping := value.(map[string]any)
	if !isMapping {
		return nil, fmt.Errorf("%w: %s must be a mapping", ErrInvalidConfig, credentialFieldName)
	}

	return &CredentialRef{
		Source: CredentialSource(stringValue(stanza, sourceFieldName)),
		Key:    stringValue(stanza, keyFieldName),
		Path:   stringValue(stanza, pathFieldName),
		Env:    stringValue(stanza, envFieldName),
	}, nil
}

// defaultKey applies the keyring key default of the instance name.
//
// Parameters:
//   - name: instance name used when the keyring key is empty.
func (ref *CredentialRef) defaultKey(name string) {
	if ref.Source == KeyringSource && ref.Key == "" {
		ref.Key = name
	}
}

// rejectUnusedFields rejects populated fields that the source ignores.
//
// Returns:
//   - error: ErrUnusedCredentialField naming the first ignored field, or nil
//     when every populated field is consumed by the configured source.
func (ref *CredentialRef) rejectUnusedFields() error {
	consumed := credentialSourceFields[ref.Source]

	for _, field := range []credentialField{
		{name: keyFieldName, value: ref.Key},
		{name: pathFieldName, value: ref.Path},
		{name: envFieldName, value: ref.Env},
	} {
		if field.value == "" || field.name == consumed {
			continue
		}

		return fmt.Errorf("%w: %q is unused", ErrUnusedCredentialField, field.name)
	}

	return nil
}

// validate applies the strict rules of the configured source.
//
// Parameters:
//   - name: instance name used to default an empty keyring key.
//   - password: configured plaintext password required by PlaintextSource.
//
// Returns:
//   - error: a wrapped sentinel error describing the invalid credential field.
func (ref *CredentialRef) validate(name, password string) error {
	err := ref.validateSource(password)
	if err != nil {
		return fmt.Errorf("validate source %q: %w", ref.Source, err)
	}

	if ref.Source == FileSource {
		err = ref.validatePath()
		if err != nil {
			return fmt.Errorf("validate source %q: %w", ref.Source, err)
		}
	}

	err = ref.rejectUnusedFields()
	if err != nil {
		return fmt.Errorf("validate source %q: %w", ref.Source, err)
	}

	ref.defaultKey(name)

	return nil
}

// validatePath requires a non-empty absolute mounted-secret path.
//
// The path is reported in errors because it is configuration, not a secret.
//
// Returns:
//   - error: ErrInvalidCredentialPath when the path is empty or relative.
func (ref *CredentialRef) validatePath() error {
	if ref.Path == "" {
		return fmt.Errorf("%w: source requires %q", ErrInvalidCredentialPath, pathFieldName)
	}

	if !path.IsAbs(ref.Path) {
		return fmt.Errorf("%w: %q is not absolute", ErrInvalidCredentialPath, ref.Path)
	}

	return nil
}

// validateSource rejects an unsupported source and a value it requires.
//
// The file path is checked separately by validatePath.
//
// Parameters:
//   - password: configured plaintext password required by PlaintextSource.
//
// Returns:
//   - error: a wrapped sentinel error when the source is unsupported or the
//     value that source requires is empty.
func (ref *CredentialRef) validateSource(password string) error {
	switch ref.Source {
	case KeyringSource, FileSource, NoneSource:
		return nil
	case EnvSource:
		if ref.Env == "" {
			return fmt.Errorf("%w: source requires %q", ErrInvalidCredentialEnv, envFieldName)
		}

		return nil
	case PlaintextSource:
		if password == "" {
			return fmt.Errorf("%w: source requires a password", ErrMissingPassword)
		}

		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidCredentialSource, ref.Source)
	}
}

// stringValue returns a string mapping value or an empty string.
//
// Parameters:
//   - raw: mapping to inspect.
//   - key: key whose value is requested.
//
// Returns:
//   - string: the string value, or an empty string when the key is absent or
//     has another type.
func stringValue(raw map[string]any, key string) string {
	value, ok := raw[key].(string)
	if !ok {
		return ""
	}

	return value
}
