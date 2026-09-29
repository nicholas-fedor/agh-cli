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
	// stamp is the observable state the source file had when it was read. Save
	// refuses to write when the file no longer matches, because a rewrite would
	// discard whatever changed it in the meantime.
	stamp fileStamp
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
)

// Load reads and parses the config file at path.
//
// If the file does not exist, an empty manager is returned. A file that exists
// but holds no content is treated the same way, so a document left empty by an
// editor or a redirect does not block the first write. If it exists but cannot
// be parsed, an error is returned.
//
// Parameters:
//   - path: filesystem path to the YAML config file.
//
// Returns:
//   - *Manager: parsed manager, or an empty manager when the file is absent or
//     holds no content.
//   - error: non-nil when the file exists but cannot be read or parsed.
func Load(path string) (*Manager, error) {
	manager := &Manager{
		path: path,
		data: &FileData{
			Credentials: CredentialsSettings{Service: DefaultCredentialService},
			Instances:   make(map[string]instance.Config),
		},
		nameOrder:      nil,
		credentialsSet: false,
		foreign:        nil,
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
//   - error: ErrInstanceAlreadyExists when name is already configured.
func (m *Manager) Add(name, host, scheme string) error {
	if m.Exists(name) {
		return fmt.Errorf("instance %q %w", name, ErrInstanceAlreadyExists)
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

// Exists reports whether the manager contains an instance with the given name.
//
// Parameters:
//   - name: instance identifier to check.
//
// Returns:
//   - bool: true when the instance exists in the in-memory configuration.
func (m *Manager) Exists(name string) bool {
	_, ok := m.data.Instances[name]

	return ok
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
	if value == "" || (field == "scheme" && value == "https") {
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
//
// Returns:
//   - error: a wrapped instance write error when a field cannot be written.
func writeInstanceSecret(builder *strings.Builder, cfg instance.Config) error {
	if cfg.Credential != nil {
		err := writeCredentialStanza(builder, cfg.Credential)
		if err != nil {
			return fmt.Errorf("write credential stanza: %w", err)
		}
	}

	if cfg.Credential != nil && cfg.Credential.Source != instance.PlaintextSource {
		return nil
	}

	err := writeOptionalInstanceLine(builder, "password", cfg.Password)
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
//
// Parameters:
//   - builder: destination for the instance fields.
//   - name: instance mapping key.
//   - cfg: instance configuration to serialize.
//
// Returns:
//   - error: a wrapped instance write error when any field cannot be written.
func writeInstance(builder *strings.Builder, name string, cfg instance.Config) error {
	err := writeInstanceLine(builder, "  %s:\n", name)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeInstanceLine(builder, "    host: %s\n", cfg.Host)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeOptionalInstanceLine(builder, "scheme", cfg.Scheme)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeOptionalInstanceLine(builder, "username", cfg.Username)
	if err != nil {
		return fmt.Errorf("%w", err)
	}

	err = writeInstanceSecret(builder, cfg)
	if err != nil {
		return fmt.Errorf("%w", err)
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

// writeForeignFields re-emits the top-level keys agh-cli does not own.
//
// They are written ahead of the keys agh-cli owns, in file order relative to one
// another. A scalar follows its key on the same line; a mapping or a sequence is
// nested under it, so the document stays valid YAML in either case.
//
// Parameters:
//   - builder: destination for the serialized fields.
//   - fields: the foreign fields in file order.
//
// Returns:
//   - error: a wrapped error when a field value cannot be serialized.
func writeForeignFields(builder *strings.Builder, fields []configField) error {
	for index := range fields {
		err := writeForeignField(builder, &fields[index])
		if err != nil {
			return fmt.Errorf("write field %q: %w", fields[index].Key.Value, err)
		}
	}

	return nil
}

// writeForeignField re-emits one foreign top-level key.
//
// The field is encoded as a one-entry mapping and handed to the YAML encoder, so
// the key and the value keep the quoting, tag, and style they were read with.
// Encoding the value as text instead would turn a quoted string containing a
// colon into a broken document, an empty string into a null, a value beginning
// with a number sign into a comment, and a literal block into a mangled scalar.
//
// Parameters:
//   - builder: destination for the serialized field.
//   - field: the foreign field.
//
// Returns:
//   - error: a wrapped error when the value cannot be serialized.
func writeForeignField(builder *strings.Builder, field *configField) error {
	document := &yaml.Node{
		Kind:    yaml.MappingNode,
		Tag:     "!!map",
		Content: []*yaml.Node{&field.Key, &field.Value},
	}

	raw, err := yaml.Marshal(document)
	if err != nil {
		return fmt.Errorf("encode value: %w", err)
	}

	_, writeErr := builder.Write(raw)
	if writeErr != nil {
		return fmt.Errorf("write encoded value: %w", writeErr)
	}

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
// [instance.Config.Validate].
//
// Parameters:
//   - name: instance identifier from the YAML mapping key.
//   - node: YAML value associated with name.
//
// Returns:
//   - error: ErrDuplicateInstance when name is already present, or a wrapped
//     error when the YAML value cannot be decoded.
func (m *Manager) addLoadedInstance(name string, node *yaml.Node) error {
	if _, exists := m.data.Instances[name]; exists {
		return fmt.Errorf("instance %q: %w", name, ErrDuplicateInstance)
	}

	var cfg instance.Config

	err := node.Decode(&cfg)
	if err != nil {
		return fmt.Errorf("decode instance %q: %w", name, err)
	}

	cfg.Name = name
	m.data.Instances[name] = cfg
	m.nameOrder = append(m.nameOrder, name)

	return nil
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
		err = m.addLoadedInstance(
			node.Content[index].Value,
			node.Content[index+1],
		)
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
	err := writeForeignFields(builder, m.foreign)
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
// authoritative serialization order.
//
// Parameters:
//   - builder: destination for the instance mappings.
//
// Returns:
//   - error: a wrapped error when the first instance cannot be written.
func (m *Manager) writeInstances(builder *strings.Builder) error {
	for _, name := range m.nameOrder {
		cfg, ok := m.data.Instances[name]
		if !ok {
			continue
		}

		err := writeInstance(builder, name, cfg)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}

	return nil
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
