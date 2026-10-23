// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package config loads, mutates, and saves the agh-cli YAML configuration.
// It preserves instance order and exposes typed AdGuard Home instance settings.
package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.yaml.in/yaml/v4"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// FileData represents the top-level structure of the agh-cli config file.
type FileData struct {
	// Credentials holds the top-level credential store settings.
	Credentials CredentialsSettings `yaml:"credentials"`
	// Instances maps each instance name to its connection configuration.
	Instances map[string]instance.Config `yaml:"instances"`
}

// instanceNode is the intermediate representation used during Load. It keeps
// the raw top-level nodes so instance order and the presence of the optional
// credentials mapping survive a load and save cycle.
type instanceNode struct {
	// Credentials contains the raw YAML value of the top-level credentials key.
	Credentials yaml.Node `yaml:"credentials"`
	// Instances contains the raw YAML value of the top-level instances key.
	Instances yaml.Node `yaml:"instances"`
}

// configField is one top-level configuration key that agh-cli does not own,
// preserved so a save never discards what an operator wrote.
//
// The key and the value are kept as parsed nodes rather than as decoded text. A
// decoded string loses the quoting, the tag, and the block style that made the
// original document valid, so writing it back verbatim would corrupt a value such
// as a quoted string containing a colon, an empty string, a leading number sign,
// or a literal block.
type configField struct {
	// Key is the raw key node, which preserves quoting and style.
	Key yaml.Node
	// Value is the raw value node, which preserves quoting, tags, and style.
	Value yaml.Node
}

// Manager owns the in-memory configuration state and its source file path.
// Mutations remain in memory until Save is called.
type Manager struct {
	// path is the source and Save destination for the YAML configuration.
	path string
	// data is the typed top-level configuration state.
	data *FileData
	// nameOrder contains instance names in file or insertion order.
	nameOrder []string
	// credentialsSet reports whether the source file declares a top-level
	// credentials mapping. Save writes that mapping only when it was present,
	// so a configuration without it round-trips unchanged.
	credentialsSet bool
	// foreign holds the top-level keys agh-cli does not own, in file order. Save
	// re-emits them ahead of the keys it owns, so an annotation or a key kept for
	// another tool survives every write.
	foreign []configField
	// undecoded holds the instances whose stanza could not be decoded, keyed by
	// name. Save writes each stanza back unchanged, so a mistyped instance is
	// never lost to a write that concerns another instance.
	undecoded map[string]undecodedInstance
	// unknown holds the keys of each instance stanza that agh-cli does not
	// read, keyed by name. Save writes them back.
	unknown map[string]unknownFields
	// stamp is the observable state the source file had when it was read. Save
	// refuses to write when the file no longer matches, because a rewrite would
	// discard whatever changed it in the meantime.
	stamp fileStamp
}

// undecodedInstance is an instance whose stanza could not be decoded.
type undecodedInstance struct {
	// key is the raw instance key node, which preserves quoting and style.
	key *yaml.Node
	// value is the raw instance stanza, which preserves quoting, tags, and style.
	value *yaml.Node
	// err is the decoding failure.
	err error
}

// aliasResolver copies retained nodes with every alias expanded.
//
// A retained entry is written on its own, apart from the document it was read
// from. An alias in it can name an anchor in a section the save regenerates, so
// the written alias would refer to nothing. Expanding each alias into a copy of
// its target keeps the written document self-contained.
type aliasResolver struct {
	// active holds the alias targets being expanded, which detects an alias that
	// refers to a node containing it.
	active map[*yaml.Node]bool
	// remaining is the number of nodes the copy may still create.
	remaining int
}

// fileStamp is the observable state of a configuration file at a point in time.
//
// Size and modification time are compared first because either alone is
// insufficient and because they are cheap: a change can preserve the size, and a
// modification time can be coarse enough to miss two writes in the same tick, or
// can be preserved deliberately by a tool that rewrites a file. Only when both
// match is the content digest compared, so the common stale case costs a single
// stat and the ambiguous case costs one read of a small file.
type fileStamp struct {
	// size is the file length in bytes.
	size int64
	// modified is the last modification time.
	modified time.Time
	// digest is a hash of the contents the file held when it was read.
	digest [sha256.Size]byte
	// hashed reports whether the digest was taken, which is false for a file
	// whose contents could not be read.
	hashed bool
	// exists reports whether the file was present when the stamp was taken.
	exists bool
}

// DefaultConfigDirName is the configuration directory name created under a
// per-user configuration root.
const DefaultConfigDirName = "agh-cli"

// DefaultConfigFileName is the configuration file name inside the configuration
// directory.
const DefaultConfigFileName = "config.yaml"

// Indentation of the nested mappings a save writes.
const (
	// InstanceIndent indents an instance entry beneath the instances key.
	instanceIndent = "  "
	// InstanceFieldIndent indents a field beneath its instance.
	instanceFieldIndent = "    "
	// CredentialFieldIndent indents a field beneath its credential stanza.
	credentialFieldIndent = "      "
)

// maxResolvedNodes bounds the nodes one retained entry may expand to, so a value
// built from nested aliases cannot exhaust memory when its aliases are expanded.
const maxResolvedNodes = 1 << 16

// Configuration persistence errors.
var (
	// ErrDuplicateInstance indicates that YAML contains a duplicate instance name.
	ErrDuplicateInstance = errors.New("duplicate instance")
	// ErrInstanceAlreadyExists indicates that an instance is already configured.
	ErrInstanceAlreadyExists = errors.New("already exists")
	// ErrInstanceNotFound indicates that an instance is not configured.
	ErrInstanceNotFound = errors.New("not found")
	// ErrInvalidInstanceMap indicates that instances is not a YAML mapping.
	ErrInvalidInstanceMap = errors.New("instances must be a mapping")
	// ErrInvalidCredentialsMap indicates that credentials is not a YAML mapping.
	ErrInvalidCredentialsMap = errors.New("credentials must be a mapping")
	// ErrConfigChanged indicates that the configuration file was modified after it
	// was read, so a save would discard whatever changed it.
	ErrConfigChanged = errors.New("config file changed since it was read")
	// ErrUnsupportedFormat indicates that a configuration path names a format
	// other than YAML.
	ErrUnsupportedFormat = errors.New("config file must be YAML")
	// ErrUnresolvableAlias indicates that a retained value holds an alias that
	// cannot be expanded for a write.
	ErrUnresolvableAlias = errors.New("retained value has an alias that cannot be expanded")
)

// yamlExtensions are the configuration file extensions agh-cli reads, compared
// without regard to letter case. A path without an extension is read as YAML.
var yamlExtensions = []string{"", ".yaml", ".yml"}

// Load reads and parses the config file at path.
//
// If the file does not exist, an empty manager is returned. A file that exists
// but holds no content is treated the same way, so a document left empty by an
// editor or a redirect does not block the first write. If it exists but cannot
// be parsed, an error is returned.
//
// Only YAML is read, and every write is YAML, so a path naming another format is
// refused before it is read. Otherwise the first write would put YAML into a
// file named for another format.
//
// An instance stanza that cannot be decoded does not fail the load. It is
// reported by [Manager.ValidationProblems] and kept for the next write, so the
// broken instance can still be removed.
//
// Parameters:
//   - path: filesystem path to the YAML config file.
//
// Returns:
//   - *Manager: parsed manager, or an empty manager when the file is absent or
//     holds no content.
//   - error: ErrUnsupportedFormat when path names a format other than YAML, or a
//     wrapped error when the file exists but cannot be read or parsed.
func Load(path string) (*Manager, error) {
	if !slices.Contains(yamlExtensions, strings.ToLower(filepath.Ext(path))) {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedFormat, filepath.Ext(path))
	}

	manager := &Manager{
		path: path,
		data: &FileData{
			Credentials: CredentialsSettings{Service: DefaultCredentialService},
			Instances:   make(map[string]instance.Config),
		},
		nameOrder:      nil,
		credentialsSet: false,
		foreign:        nil,
		undecoded:      make(map[string]undecodedInstance),
		unknown:        make(map[string]unknownFields),
		stamp:          fileStamp{},
	}

	// The file is opened once and every observation comes from that handle, so
	// the bytes parsed and the recorded stamp describe the same content. Reading
	// the path again could observe a different file, and a save would then
	// compare against a state it never loaded.
	contents, info, readErr := readConfigSource(path)
	if readErr != nil {
		if errors.Is(readErr, os.ErrNotExist) {
			return manager, nil
		}

		return nil, fmt.Errorf("%w", readErr)
	}

	// The blank test uses the same bytes the parse uses, so a document with no
	// content is never handed to the decoder. The stamp is still recorded, so a
	// blank file written by someone else between this load and the first write is
	// reported as a change rather than silently replaced.
	if len(bytes.TrimSpace(contents)) == 0 {
		manager.stamp = stampFrom(info, contents)

		return manager, nil
	}

	loadErr := manager.decode(contents)
	if loadErr != nil {
		return nil, fmt.Errorf("%w", loadErr)
	}

	manager.foreign = captureForeignFields(contents)
	manager.stamp = stampFrom(info, contents)

	return manager, nil
}

// readConfigSource opens a configuration file once and reads it whole.
//
// The returned information comes from the same handle the contents were read
// through, so a caller that records a stamp from it describes exactly the bytes
// it parsed.
//
// Parameters:
//   - path: filesystem path of the configuration file.
//
// Returns:
//   - []byte: the file contents.
//   - [os.FileInfo]: the information observed while reading.
//   - error: a wrapped error when the file is missing, is not a regular file, or
//     cannot be read.
func readConfigSource(path string) ([]byte, fs.FileInfo, error) {
	file, openErr := os.Open(path)
	if openErr != nil {
		return nil, nil, fmt.Errorf("open config %q: %w", path, openErr)
	}

	defer func() { _ = file.Close() }()

	info, statErr := file.Stat()
	if statErr != nil {
		return nil, nil, fmt.Errorf("inspect config %q: %w", path, statErr)
	}

	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("inspect config %q: %w", path, ErrConfigNotRegular)
	}

	contents, readErr := io.ReadAll(file)
	if readErr != nil {
		return nil, nil, fmt.Errorf("read config %q: %w", path, readErr)
	}

	return contents, info, nil
}

// stampFrom records the observable state of an already-read file.
//
// The information and the contents come from the same handle, so the stamp
// cannot describe a different file than the one that was parsed.
//
// Parameters:
//   - info: file information obtained while reading the contents.
//   - contents: the contents the information describes.
//
// Returns:
//   - fileStamp: the recorded state, including a digest of the contents.
func stampFrom(info fs.FileInfo, contents []byte) fileStamp {
	return fileStamp{
		size:     info.Size(),
		modified: info.ModTime(),
		digest:   sha256.Sum256(contents),
		hashed:   true,
		exists:   true,
	}
}

// unchanged reports whether a file still matches a previously taken stamp.
//
// Size and modification time are compared first, because a difference in either
// settles the question without reading the file. When both match, the contents
// are hashed and compared, which is what catches a rewrite that preserved the
// size and the timestamp.
//
// A file that cannot be read is reported as changed. Guessing that an
// unreadable file is unchanged would let a save overwrite it, which is exactly
// the loss this guard exists to prevent.
//
// Parameters:
//   - stamp: the state recorded when the file was read.
//   - path: filesystem path to re-inspect.
//
// Returns:
//   - bool: true when the file still matches the recorded state.
func (s fileStamp) unchanged(path string) bool {
	latest, err := stampPath(path)
	if err != nil {
		return false
	}

	if s.size != latest.size || !s.modified.Equal(latest.modified) || s.exists != latest.exists {
		return false
	}

	// Both cheap observations match, so the contents decide. A stamp taken
	// without a digest cannot be compared this way, and reports unchanged rather
	// than blocking every save over a file that is almost certainly the same.
	if !s.hashed || !latest.hashed {
		return true
	}

	return s.digest == latest.digest
}

// stampPath records the observable state of a configuration file on disk.
//
// Parameters:
//   - path: filesystem path to stamp.
//
// Returns:
//   - fileStamp: the state observed.
//   - error: a wrapped error when the file cannot be inspected or read.
func stampPath(path string) (fileStamp, error) {
	info, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, fmt.Errorf("inspect config %q: %w", path, err)
	}

	contents, readErr := os.ReadFile(path)
	if readErr != nil {
		return fileStamp{}, fmt.Errorf("read config %q: %w", path, readErr)
	}

	return stampFrom(info, contents), nil
}

// stampWritten records the state of a file this manager has just written.
//
// A file that cannot be stamped leaves the manager with an absent stamp, which
// makes a later save treat the path as a first write rather than block on a
// state it cannot confirm.
//
// Parameters:
//   - path: filesystem path that was written.
//
// Returns:
//   - fileStamp: the state observed, or an absent stamp.
func stampWritten(path string) fileStamp {
	stamp, err := stampPath(resolveWriteTarget(path))
	if err != nil {
		return fileStamp{}
	}

	return stamp
}

// captureForeignFields returns the top-level keys agh-cli does not own, in file
// order.
//
// The document is re-read as a node rather than the typed view, because the
// typed view is exactly the set of keys that would otherwise be dropped. A
// configuration that carries an annotation, or a key another tool reads, keeps
// it across every save.
//
// Parameters:
//   - data: raw configuration file contents.
//
// Returns:
//   - []configField: the foreign keys in file order, or nil when the document is
//     not a top-level mapping.
func captureForeignFields(data []byte) []configField {
	var document yaml.Node

	if yaml.Unmarshal(data, &document) != nil {
		return nil
	}

	mapping := documentMapping(&document)
	if mapping == nil {
		return nil
	}

	fields := make([]configField, 0, len(mapping.Content)/2)

	for index := 0; index+1 < len(mapping.Content); index += 2 {
		key := mapping.Content[index].Value

		if key == credentialsFieldName || key == instancesFieldName {
			continue
		}

		fields = append(fields, configField{
			Key:   *mapping.Content[index],
			Value: *mapping.Content[index+1],
		})
	}

	if len(fields) == 0 {
		return nil
	}

	return fields
}

// documentMapping returns the top-level mapping of a parsed document, or nil
// when the document is empty or is not a mapping.
//
// Parameters:
//   - document: parsed document node.
//
// Returns:
//   - *yaml.Node: the mapping node, or nil.
func documentMapping(document *yaml.Node) *yaml.Node {
	node := document
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil
		}

		node = node.Content[0]
	}

	if node.Kind != yaml.MappingNode {
		return nil
	}

	return node
}

// Add inserts a new instance configuration into the manager's in-memory state.
// It does not write the change to disk.
//
// An added instance carries no credentials. A username and a password are
// authentication details owned by the credential workflow, so they are set
// afterwards rather than accepted as add-time input.
//
// Parameters:
//   - name: unique instance identifier.
//   - host: AdGuard Home hostname or IP address.
//   - scheme: URL scheme used to contact the instance; an empty value becomes
//     HTTPS.
//
// Returns:
//   - error: ErrInstanceAlreadyExists when name is already configured, or a
//     wrapped [instance.ErrConflictingInstance] when name differs from a
//     configured name only by letter case.
func (m *Manager) Add(name, host, scheme string) error {
	if m.Exists(name) {
		return fmt.Errorf("instance %q %w", name, ErrInstanceAlreadyExists)
	}

	if conflict, found := conflictingName(m.nameOrder, name); found {
		return fmt.Errorf("%w: %q and %q", instance.ErrConflictingInstance, conflict, name)
	}

	if scheme == "" {
		scheme = "https"
	}

	m.data.Instances[name] = instance.Config{
		Name:       name,
		Host:       host,
		Scheme:     scheme,
		Username:   "",
		Password:   "",
		Credential: nil,
	}
	m.nameOrder = append(m.nameOrder, name)

	return nil
}

// Configs returns the decoded instance configurations in file order.
//
// An instance whose stanza could not be decoded has no configuration, so it is
// reported rather than skipped. A command that selects instances must never fall
// back to another instance because one stanza is mistyped.
//
// Returns:
//   - []instance.Config: the decoded configurations in file order.
//   - error: a joined error naming every instance whose stanza could not be
//     decoded.
func (m *Manager) Configs() ([]instance.Config, error) {
	configs := make([]instance.Config, 0, len(m.nameOrder))

	var errs []error

	for _, name := range m.nameOrder {
		if undecoded, ok := m.undecoded[name]; ok {
			errs = append(errs, fmt.Errorf("instance %q: %w", name, undecoded.err))

			continue
		}

		configs = append(configs, m.data.Instances[name])
	}

	return configs, errors.Join(errs...)
}

// Exists reports whether the manager contains an instance with the given name.
//
// Parameters:
//   - name: instance identifier to check.
//
// An instance whose stanza could not be decoded still exists, so it can be
// removed.
//
// Returns:
//   - bool: true when the instance exists in the in-memory configuration.
func (m *Manager) Exists(name string) bool {
	return slices.Contains(m.nameOrder, name)
}

// Instances returns a snapshot of all in-memory instance configurations.
//
// Returns:
//   - map[string]instance.Config: an independent map containing every instance.
func (m *Manager) Instances() map[string]instance.Config {
	out := make(map[string]instance.Config, len(m.data.Instances))
	maps.Copy(out, m.data.Instances)

	return out
}

// OrderedNames returns a snapshot of instance names in configuration order.
//
// Returns:
//   - []string: names in file order, with later additions appended in insertion
//     order.
func (m *Manager) OrderedNames() []string {
	out := make([]string, 0, len(m.nameOrder))

	out = append(out, m.nameOrder...)

	return out
}

// Remove deletes an instance configuration from the manager's in-memory
// state. It does not write the change to disk.
//
// Parameters:
//   - name: instance identifier to remove.
//
// Returns:
//   - error: ErrInstanceNotFound when the instance is not configured.
func (m *Manager) Remove(name string) error {
	if !m.Exists(name) {
		return fmt.Errorf("instance %q %w", name, ErrInstanceNotFound)
	}

	delete(m.data.Instances, name)
	delete(m.undecoded, name)
	delete(m.unknown, name)

	m.nameOrder = filterSlice(m.nameOrder, func(n string) bool { return n != name })

	return nil
}

// writeBuilderLine formats and appends one configuration line.
//
// Parameters:
//   - builder: destination for the formatted line.
//   - format: formatting directive for the line.
//   - args: values referenced by format.
//
// Returns:
//   - error: a wrapped write error when formatting or appending fails.
func writeBuilderLine(builder *strings.Builder, format string, args ...any) error {
	_, err := fmt.Fprintf(builder, format, args...)
	if err != nil {
		return fmt.Errorf("write config line: %w", err)
	}

	return nil
}

// writeInstanceLine formats and appends one instance configuration line.
//
// Parameters:
//   - builder: destination for the formatted line.
//   - format: formatting directive for the line.
//   - args: values referenced by format.
//
// Returns:
//   - error: a wrapped instance write error when formatting or appending fails.
func writeInstanceLine(builder *strings.Builder, format string, args ...any) error {
	err := writeBuilderLine(builder, format, args...)
	if err != nil {
		return fmt.Errorf("write instance: %w", err)
	}

	return nil
}

// writeOptionalInstanceLine appends an optional instance configuration field.
//
// Empty values and the default HTTPS scheme are omitted.
//
// Parameters:
//   - builder: destination for the formatted line.
//   - field: YAML field name.
//   - value: YAML field value.
//
// Returns:
//   - error: a wrapped instance write error when formatting or appending fails.
func writeOptionalInstanceLine(builder *strings.Builder, field, value string) error {
	if value == "" || (field == schemeFieldName && value == "https") {
		return nil
	}

	err := writeInstanceLine(builder, "    %s: %s\n", field, value)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// writeInstanceSecret appends the credential stanza and password of one
// instance.
//
// An instance without a credential reference keeps its legacy plaintext
// password and writes no stanza. An explicit instance.PlaintextSource also
// keeps its password, because that source is configured to read the legacy
// password field and the configuration would otherwise be invalid after a save.
// Every other source owns the secret outside the configuration, so no password
// is serialized for them.
//
// Parameters:
//   - builder: destination for the credential fields.
//   - cfg: instance configuration to serialize.
//   - unknown: entries of the credential stanza agh-cli does not read.
//
// Returns:
//   - error: a wrapped instance write error when a field cannot be written.
func writeInstanceSecret(builder *strings.Builder, cfg instance.Config, unknown []configField) error {
	if cfg.Credential != nil {
		err := writeCredentialStanza(builder, cfg.Credential, unknown)
		if err != nil {
			return fmt.Errorf("write credential stanza: %w", err)
		}
	}

	if cfg.Credential != nil && cfg.Credential.Source != instance.PlaintextSource {
		return nil
	}

	err := writeOptionalInstanceLine(builder, passwordFieldName, cfg.Password)
	if err != nil {
		return fmt.Errorf("write password: %w", err)
	}

	return nil
}

// writeInstance appends one instance's ordered configuration fields.
//
// An instance whose credential source is not instance.PlaintextSource never
// serializes its password, because that source owns the secret. An instance
// without a reference, and an explicit plaintext source, keep their password.
// The keys agh-cli does not read follow the fields it owns, as they were read.
//
// Parameters:
//   - builder: destination for the instance fields.
//   - name: instance mapping key.
//   - cfg: instance configuration to serialize.
//   - unknown: entries of the instance stanza agh-cli does not read.
//
// Returns:
//   - error: a wrapped instance write error when any field cannot be written.
func writeInstance(
	builder *strings.Builder,
	name string,
	cfg instance.Config,
	unknown unknownFields,
) error {
	err := writeInstanceLine(builder, "  %s:\n", name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeOptionalInstanceLine(builder, hostFieldName, cfg.Host)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeOptionalInstanceLine(builder, schemeFieldName, cfg.Scheme)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeOptionalInstanceLine(builder, usernameFieldName, cfg.Username)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeInstanceSecret(builder, cfg, unknown.credential)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeIndentedFields(builder, unknown.instance, instanceFieldIndent)
	if err != nil {
		return fmt.Errorf("write unknown fields: %w", err)
	}

	return nil
}

// Save writes the current in-memory configuration to the manager's file path.
//
// Save serializes instances in nameOrder. It omits empty or HTTPS schemes, and
// omits the password of every instance whose credential source does not read
// it, so a secret moved into the keyring, a mounted file, or the environment is
// never written back. An instance without a credential reference, and an
// explicit instance.PlaintextSource, keep their password because that source
// reads the password field. Map entries absent from nameOrder are not
// serialized.
//
// The file is replaced atomically through a private temporary file, so an
// interrupted write cannot truncate the only configuration copy, and the mode
// of a pre-existing file is tightened instead of merely applied at creation.
//
// Returns:
//   - error: a wrapped error when formatting or writing the file fails.
func (m *Manager) Save() error {
	// A file that existed when this manager was loaded must still be the file
	// that was read, or a rewrite would discard whatever changed it since. A
	// file that was absent at load is a first write, not a stale one, so it is
	// created rather than refused.
	if m.stamp.exists && !m.stamp.unchanged(resolveWriteTarget(m.path)) {
		return fmt.Errorf("write config %q: %w", m.path, ErrConfigChanged)
	}

	var builder strings.Builder

	err := m.writeDocument(&builder)
	if err != nil {
		return fmt.Errorf("serialize config %q: %w", m.path, err)
	}

	err = writeFileAtomic(m.path, []byte(builder.String()))
	if err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	// The manager now matches the file, so a second save in the same run is not
	// mistaken for an external change.
	m.stamp = stampWritten(m.path)

	return nil
}

// writeTempConfig writes data to temp, flushes it to storage, and closes temp.
// The close error is reported even when the flush succeeded, so a failed write
// is never hidden by a successful close.
//
// Parameters:
//   - temp: open temporary configuration file.
//   - data: complete file contents.
//
// Returns:
//   - error: a wrapped error when writing, flushing, or closing fails.
func writeTempConfig(temp *os.File, data []byte) error {
	_, writeErr := temp.Write(data)
	if writeErr != nil {
		return errors.Join(
			fmt.Errorf("write temp config: %w", writeErr),
			temp.Close(),
		)
	}

	return errors.Join(
		wrapTempError("sync temp config", temp.Sync()),
		wrapTempError("close temp config", temp.Close()),
	)
}

// writeTempFile writes data to a private temporary file beside path.
//
// The temporary file is created next to the destination so the replacement
// stays on one filesystem, and it is removed when the write fails.
//
// Parameters:
//   - path: destination file path.
//   - data: complete file contents.
//
// Returns:
//   - string: path of the temporary file, or an empty string on failure.
//   - error: a wrapped error when the temporary file cannot be created or
//     written.
func writeTempFile(path string, data []byte) (string, error) {
	temp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+tempFilePattern)
	if err != nil {
		return "", fmt.Errorf("create temp config: %w", err)
	}

	err = writeTempConfig(temp, data)
	if err != nil {
		return "", errors.Join(err, os.Remove(temp.Name()))
	}

	return temp.Name(), nil
}

// writeFileAtomic replaces path with data through a private temporary file.
//
// A missing parent directory is created first, so the first save into a fresh
// per-user configuration directory succeeds instead of failing on the temporary
// file. An existing directory keeps its own permissions, because a save must
// not widen or narrow a directory the operator created.
//
// The replacement file carries mode 0600, and the destination permissions are
// tightened explicitly, so a configuration that was world-readable before the
// save is private afterwards.
//
// A symlinked destination is resolved before the replace. A rename acts on the
// link itself rather than writing through it, so renaming onto the literal path
// would destroy the link and leave the file the operator pointed at unchanged.
// Resolving first keeps the link intact and updates the file it names.
//
// Parameters:
//   - path: destination file path.
//   - data: complete file contents.
//
// Returns:
//   - error: a wrapped error when the parent directory cannot be created, the
//     temporary file cannot be created, the rename fails, or the destination
//     permissions cannot be tightened.
func writeFileAtomic(path string, data []byte) error {
	target := resolveWriteTarget(path)

	err := os.MkdirAll(filepath.Dir(target), configDirMode)
	if err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	tempName, err := writeTempFile(target, data)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = os.Rename(tempName, target)
	if err != nil {
		return errors.Join(fmt.Errorf("replace config: %w", err), os.Remove(tempName))
	}

	err = os.Chmod(target, configFileMode)
	if err != nil {
		return fmt.Errorf("tighten config permissions: %w", err)
	}

	return nil
}

// resolveWriteTarget returns the file a save should actually replace.
//
// A symlink is followed so the replace lands on the file the operator named.
// Resolution is best effort: a path that cannot be resolved, such as a symlink
// whose target does not exist, is used as given, which preserves the behavior
// of creating a new file at that path.
//
// Parameters:
//   - path: destination file path.
//
// Returns:
//   - string: the path to replace, which is the resolved target when path is a
//     symlink.
func resolveWriteTarget(path string) string {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return path
	}

	return resolved
}

// wrapTempError wraps a temporary-file error with its failing stage.
//
// Parameters:
//   - stage: name of the operation that failed.
//   - err: error returned by the operation.
//
// Returns:
//   - error: the wrapped error, or nil when err is nil.
func wrapTempError(stage string, err error) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %w", stage, err)
}

// addLoadedInstance decodes and records one instance mapping in order.
//
// The mapping key becomes Config.Name. This helper does not call
// [instance.Config.Validate]. A stanza that cannot be decoded is recorded rather
// than refused, and its unknown fields are recorded as well, so both are
// reported by [Manager.ValidationProblems].
//
// The decoding failure is reported by the stanza location and the expected
// schema only. The decoder's own message quotes the offending value, and a
// mistyped stanza can hold a secret, such as a password written where the
// credential mapping belongs.
//
// Parameters:
//   - key: YAML key node naming the instance.
//   - node: YAML value associated with key.
//
// Returns:
//   - error: ErrDuplicateInstance when the name is already present.
func (m *Manager) addLoadedInstance(key, node *yaml.Node) error {
	name := key.Value
	if m.Exists(name) {
		return fmt.Errorf("instance %q: %w", name, ErrDuplicateInstance)
	}

	m.nameOrder = append(m.nameOrder, name)

	if unknown := stanzaUnknownFields(node); !unknown.empty() {
		m.unknown[name] = unknown
	}

	cfg, decoded := decodeInstance(node)
	if !decoded {
		m.undecoded[name] = undecodedInstance{
			key:   key,
			value: node,
			err: fmt.Errorf(
				"%w: stanza at line %d, column %d must map string settings and an optional credential mapping",
				instance.ErrInvalidConfig,
				key.Line,
				key.Column,
			),
		}

		return nil
	}

	cfg.Name = name
	m.data.Instances[name] = cfg

	return nil
}

// decodeInstance decodes one instance stanza.
//
// Only whether the stanza decoded is reported. The decoder's message quotes the
// offending value, which can be a secret, so the caller describes the failure
// itself.
//
// Parameters:
//   - node: YAML value of one instance.
//
// Returns:
//   - instance.Config: the decoded configuration, or the zero configuration
//     when the stanza does not decode.
//   - bool: true when the stanza decoded.
func decodeInstance(node *yaml.Node) (instance.Config, bool) {
	var cfg instance.Config

	if node.Decode(&cfg) != nil {
		return instance.Config{}, false
	}

	return cfg, true
}

// decode fills the manager from a parsed configuration document.
//
// Parameters:
//   - contents: complete configuration file contents.
//
// Returns:
//   - error: a wrapped error when the document cannot be parsed or decoded.
func (m *Manager) decode(contents []byte) error {
	var node instanceNode

	parseErr := yaml.Unmarshal(contents, &node)
	if parseErr != nil {
		return fmt.Errorf("parse config: %w", parseErr)
	}

	loadErr := m.loadCredentials(&node.Credentials)
	if loadErr != nil {
		return fmt.Errorf("load credentials: %w", loadErr)
	}

	loadErr = m.loadInstances(&node.Instances)
	if loadErr != nil {
		return fmt.Errorf("load instances: %w", loadErr)
	}

	return nil
}

// editableInstance returns the configuration of one instance a mutation changes.
//
// An instance whose stanza could not be decoded has no configuration to change,
// so its decoding failure is reported rather than a missing instance.
//
// Parameters:
//   - name: instance identifier to look up.
//
// Returns:
//   - instance.Config: the decoded configuration.
//   - error: ErrInstanceNotFound when name is not configured, or a wrapped
//     [instance.ErrInvalidConfig] when its stanza could not be decoded.
func (m *Manager) editableInstance(name string) (instance.Config, error) {
	if undecoded, ok := m.undecoded[name]; ok {
		return instance.Config{}, fmt.Errorf("instance %q: %w", name, undecoded.err)
	}

	cfg, ok := m.data.Instances[name]
	if !ok {
		return instance.Config{}, fmt.Errorf("instance %q %w", name, ErrInstanceNotFound)
	}

	return cfg, nil
}

// loadInstances replaces manager instances from a YAML instances mapping.
//
// Mapping order is retained in nameOrder. A missing instances value is treated
// as an empty mapping. The credential settings are left untouched.
//
// Parameters:
//   - node: YAML value for the top-level instances key.
//
// Returns:
//   - error: a wrapped error when the mapping is invalid or an entry cannot be
//     added.
func (m *Manager) loadInstances(node *yaml.Node) error {
	err := validateInstanceMap(node)
	if err != nil {
		return fmt.Errorf("validate instance map: %w", err)
	}

	m.data.Instances = make(map[string]instance.Config, len(node.Content)/2)
	m.nameOrder = make([]string, 0, len(node.Content)/2)

	for index := 0; index < len(node.Content); index += 2 {
		err = m.addLoadedInstance(node.Content[index], node.Content[index+1])
		if err != nil {
			return fmt.Errorf("add loaded instance: %w", err)
		}
	}

	return nil
}

// writeDocument serializes the whole configuration, foreign keys first.
//
// Parameters:
//   - builder: destination for the serialized document.
//
// Returns:
//   - error: a wrapped error when a section cannot be serialized.
func (m *Manager) writeDocument(builder *strings.Builder) error {
	err := writeIndentedFields(builder, m.foreign, "")
	if err != nil {
		return fmt.Errorf("write foreign fields: %w", err)
	}

	if m.credentialsSet {
		writeErr := writeCredentials(builder, m.data.Credentials)
		if writeErr != nil {
			return fmt.Errorf("write credentials: %w", writeErr)
		}
	}

	_, _ = builder.WriteString("instances:\n")

	err = m.writeInstances(builder)
	if err != nil {
		return fmt.Errorf("write instances: %w", err)
	}

	return nil
}

// writeInstances appends every instance mapping in name order.
//
// Map entries absent from nameOrder are skipped, because nameOrder is the
// authoritative serialization order. A stanza that could not be decoded is
// written back unchanged.
//
// Parameters:
//   - builder: destination for the instance mappings.
//
// Returns:
//   - error: a wrapped error when the first instance cannot be written.
func (m *Manager) writeInstances(builder *strings.Builder) error {
	for _, name := range m.nameOrder {
		err := m.writeNamedInstance(builder, name)
		if err != nil {
			return fmt.Errorf("write instance %q: %w", name, err)
		}
	}

	return nil
}

// writeNamedInstance appends the mapping of one instance in name order.
//
// A stanza that could not be decoded is written back unchanged, and a name with
// no configuration is skipped.
//
// Parameters:
//   - builder: destination for the instance mapping.
//   - name: instance whose mapping is written.
//
// Returns:
//   - error: a wrapped error when the mapping cannot be written.
func (m *Manager) writeNamedInstance(builder *strings.Builder, name string) error {
	if undecoded, ok := m.undecoded[name]; ok {
		err := writeUndecodedInstance(builder, undecoded)
		if err != nil {
			return fmt.Errorf("%w", err)
		}

		return nil
	}

	cfg, ok := m.data.Instances[name]
	if !ok {
		return nil
	}

	err := writeInstance(builder, name, cfg, m.unknown[name])
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// writeUndecodedInstance appends one instance stanza exactly as it was read.
//
// Parameters:
//   - builder: destination for the instance mapping.
//   - undecoded: instance whose raw key and stanza are written.
//
// Returns:
//   - error: a wrapped error when the stanza cannot be encoded.
func writeUndecodedInstance(builder *strings.Builder, undecoded undecodedInstance) error {
	err := writeIndentedField(builder, undecoded.key, undecoded.value, instanceIndent)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	return nil
}

// writeIndentedFields appends parsed entries beneath an enclosing mapping.
//
// Parameters:
//   - builder: destination for the entries.
//   - fields: parsed entries to write, in order.
//   - indent: indentation of each entry.
//
// Returns:
//   - error: a wrapped error naming the first entry that cannot be encoded.
func writeIndentedFields(builder *strings.Builder, fields []configField, indent string) error {
	for index := range fields {
		err := writeIndentedField(builder, &fields[index].Key, &fields[index].Value, indent)
		if err != nil {
			return fmt.Errorf("write field %q: %w", fields[index].Key.Value, err)
		}
	}

	return nil
}

// writeIndentedField appends one parsed entry beneath an enclosing mapping.
//
// The entry is encoded as a single-entry mapping and every line is indented by
// the same amount. Shifting a whole block uniformly keeps its structure,
// including that of block scalars, and the parsed nodes keep their quoting,
// tags, and style.
//
// The entry is written from a copy whose aliases are expanded and whose anchors
// are dropped, because an alias can name an anchor in a section the save
// regenerates. The retained nodes themselves are left unchanged.
//
// Parameters:
//   - builder: destination for the entry.
//   - key: parsed key node.
//   - value: parsed value node.
//   - indent: indentation of the entry.
//
// Returns:
//   - error: a wrapped ErrUnresolvableAlias when an alias cannot be expanded,
//     or a wrapped error when the entry cannot be encoded.
func writeIndentedField(builder *strings.Builder, key, value *yaml.Node, indent string) error {
	resolver := aliasResolver{active: make(map[*yaml.Node]bool), remaining: maxResolvedNodes}

	resolvedKey, err := resolver.resolve(key)
	if err != nil {
		return fmt.Errorf("expand key aliases: %w", err)
	}

	resolvedValue, err := resolver.resolve(value)
	if err != nil {
		return fmt.Errorf("expand value aliases: %w", err)
	}

	raw, err := yaml.Marshal(&yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: []*yaml.Node{resolvedKey, resolvedValue},
	})
	if err != nil {
		return fmt.Errorf("encode entry: %w", err)
	}

	for line := range strings.Lines(string(raw)) {
		if strings.TrimSpace(line) != "" {
			_, _ = builder.WriteString(indent)
		}

		_, _ = builder.WriteString(line)
	}

	return nil
}

// resolve returns a deep copy of node with every alias replaced by a copy of its
// target and every anchor cleared.
//
// Parameters:
//   - node: retained node to copy. It is not modified.
//
// Returns:
//   - *yaml.Node: the expanded copy.
//   - error: a wrapped ErrUnresolvableAlias when an alias refers to a node that
//     contains it, has no target, or expands beyond [maxResolvedNodes].
func (r *aliasResolver) resolve(node *yaml.Node) (*yaml.Node, error) {
	r.remaining--
	if r.remaining < 0 {
		return nil, fmt.Errorf("%w: it expands beyond %d nodes", ErrUnresolvableAlias, maxResolvedNodes)
	}

	if node.Kind == yaml.AliasNode {
		resolved, err := r.resolveAlias(node)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		return resolved, nil
	}

	copied := *node

	copied.Anchor = ""
	copied.Content = make([]*yaml.Node, 0, len(node.Content))

	for _, child := range node.Content {
		resolved, err := r.resolve(child)
		if err != nil {
			return nil, fmt.Errorf("%w", err)
		}

		copied.Content = append(copied.Content, resolved)
	}

	return &copied, nil
}

// resolveAlias returns an expanded copy of the target of one alias node.
//
// Parameters:
//   - alias: alias node to expand.
//
// Returns:
//   - *yaml.Node: the expanded copy of the alias target.
//   - error: a wrapped ErrUnresolvableAlias when the alias has no target or
//     refers to a node that contains it.
func (r *aliasResolver) resolveAlias(alias *yaml.Node) (*yaml.Node, error) {
	target := alias.Alias
	if target == nil {
		return nil, fmt.Errorf("%w: alias %q has no target", ErrUnresolvableAlias, alias.Value)
	}

	if r.active[target] {
		return nil, fmt.Errorf("%w: alias %q refers to a value containing it", ErrUnresolvableAlias, alias.Value)
	}

	r.active[target] = true
	defer delete(r.active, target)

	resolved, err := r.resolve(target)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return resolved, nil
}

// validateInstanceMap verifies that a YAML node is a complete mapping.
//
// A zero node is accepted as a missing or empty instances value. Any other
// node must have mapping kind and an even number of content nodes.
//
// Parameters:
//   - node: YAML value to validate.
//
// Returns:
//   - error: ErrInvalidInstanceMap when the value is not a complete mapping.
func validateInstanceMap(node *yaml.Node) error {
	if isZeroNode(node) {
		return nil
	}

	if node.Kind != yaml.MappingNode || len(node.Content)%2 != 0 {
		return ErrInvalidInstanceMap
	}

	return nil
}

// filterSlice returns the elements for which keep returns true.
//
// The filtering operation preserves input order and always returns a new slice.
//
// Parameters:
//   - s: values to filter.
//   - keep: predicate applied to each value.
//
// Returns:
//   - []T: retained values in their original order.
func filterSlice[T any](s []T, keep func(T) bool) []T {
	out := make([]T, 0, len(s))
	for _, v := range s {
		if keep(v) {
			out = append(out, v)
		}
	}

	return out
}

// isZeroNode reports whether node is an absent YAML value.
//
// Parameters:
//   - node: YAML value to inspect.
//
// Returns:
//   - bool: true when the node carries no value at all.
func isZeroNode(node *yaml.Node) bool {
	return node.Kind == 0 && len(node.Content) == 0
}
