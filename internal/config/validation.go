// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"errors"
	"fmt"
	"slices"

	"go.yaml.in/yaml/v4"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// ValidationProblem reports one problem with a configured instance.
type ValidationProblem struct {
	// Err is the problem found.
	Err error
	// Instance is the name of the instance the problem belongs to.
	Instance string
}

// unknownFields holds the keys of one instance stanza that agh-cli does not
// read.
//
// The keys are reported as problems, and a write keeps them, so a misspelled
// key or one kept for another tool is never silently dropped.
type unknownFields struct {
	// instance holds the unknown entries of the instance stanza.
	instance []configField
	// credential holds the unknown entries of the credential stanza.
	credential []configField
}

// ErrUnknownField indicates that an instance or credential stanza names a key
// agh-cli does not read.
var ErrUnknownField = errors.New("unknown field")

// instanceFields are the keys an instance stanza may hold.
var instanceFields = []string{
	hostFieldName,
	schemeFieldName,
	usernameFieldName,
	passwordFieldName,
	credentialFieldName,
}

// credentialFields are the keys a credential stanza may hold.
var credentialFields = []string{
	sourceFieldName,
	keyFieldName,
	pathFieldName,
	envFieldName,
}

// ValidationProblems reports the problems with the configured instances.
//
// Instances are validated when a command builds its catalog, so an invalid
// instance otherwise surfaces long after the file was read. Reporting the
// problems without failing keeps the configuration usable, because refusing the
// load would make a broken instance impossible to remove.
//
// A stanza that cannot be decoded and a configuration that fails validation make
// an instance unusable. An unknown field and a name that differs from an earlier
// one only by letter case are reported as well, so a misspelled key is never
// silently ignored.
//
// The problems follow the file order of the instances, so repeated runs report
// the same problems in the same order.
//
// Returns:
//   - []ValidationProblem: the problems found, or nil when every instance is
//     usable and well formed.
func (m *Manager) ValidationProblems() []ValidationProblem {
	var problems []ValidationProblem

	for index, name := range m.nameOrder {
		for _, err := range m.instanceProblems(name, m.nameOrder[:index]) {
			problems = append(problems, ValidationProblem{Instance: name, Err: err})
		}
	}

	return problems
}

// instanceProblems returns the problems with one configured instance.
//
// Parameters:
//   - name: instance to inspect.
//   - earlier: instance names that precede name in file order.
//
// Returns:
//   - []error: the problems found, in a fixed order.
func (m *Manager) instanceProblems(name string, earlier []string) []error {
	var problems []error

	if undecoded, ok := m.undecoded[name]; ok {
		problems = append(problems, undecoded.err)
	}

	problems = append(problems, m.unknown[name].problems()...)

	if conflict, found := conflictingName(earlier, name); found {
		problems = append(problems, fmt.Errorf(
			"%w: %q and %q",
			instance.ErrConflictingInstance,
			conflict,
			name,
		))
	}

	if cfg, ok := m.data.Instances[name]; ok {
		_, err := cfg.Validate()
		if err != nil {
			problems = append(problems, err)
		}
	}

	return problems
}

// conflictingName returns the name in names that differs from name only by
// letter case.
//
// Parameters:
//   - names: configured instance names.
//   - name: instance name to compare.
//
// Returns:
//   - string: the conflicting name, or an empty string when none conflicts.
//   - bool: true when a name conflicts with name.
func conflictingName(names []string, name string) (string, bool) {
	for _, existing := range names {
		if instance.ID(existing).ConflictsWith(instance.ID(name)) {
			return existing, true
		}
	}

	return "", false
}

// stanzaUnknownFields collects the keys of an instance stanza that agh-cli does
// not read, including those of its credential stanza.
//
// Parameters:
//   - node: YAML value of one instance.
//
// Returns:
//   - unknownFields: the unknown keys with their values, in file order.
func stanzaUnknownFields(node *yaml.Node) unknownFields {
	fields := unknownFields{
		instance:   unknownKeys(node, instanceFields),
		credential: nil,
	}

	if credential := mappingValue(node, credentialFieldName); credential != nil {
		fields.credential = unknownKeys(credential, credentialFields)
	}

	return fields
}

// unknownKeys returns the entries of a mapping node whose key is not in known.
//
// Parameters:
//   - node: YAML value to inspect. A node that is not a mapping has no keys.
//   - known: keys the mapping may hold.
//
// Returns:
//   - []configField: the unknown entries as parsed nodes, in file order.
func unknownKeys(node *yaml.Node, known []string) []configField {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	var fields []configField

	for index := 0; index+1 < len(node.Content); index += 2 {
		if !slices.Contains(known, node.Content[index].Value) {
			fields = append(fields, configField{
				Key:   *node.Content[index],
				Value: *node.Content[index+1],
			})
		}
	}

	return fields
}

// empty reports whether the stanza held no unknown key.
//
// Returns:
//   - bool: true when neither the instance nor its credential stanza held an
//     unknown key.
func (u unknownFields) empty() bool {
	return len(u.instance) == 0 && len(u.credential) == 0
}

// problems reports one ErrUnknownField per unknown key.
//
// Returns:
//   - []error: the problems in file order, instance keys first.
func (u unknownFields) problems() []error {
	problems := make([]error, 0, len(u.instance)+len(u.credential))

	for index := range u.instance {
		problems = append(problems, fmt.Errorf("%w: %q", ErrUnknownField, u.instance[index].Key.Value))
	}

	for index := range u.credential {
		problems = append(problems, fmt.Errorf(
			"%w: %q",
			ErrUnknownField,
			credentialFieldName+"."+u.credential[index].Key.Value,
		))
	}

	return problems
}

// mappingValue returns the value of key in a mapping node.
//
// Parameters:
//   - node: YAML value to search. A node that is not a mapping holds no keys.
//   - key: key whose value is requested.
//
// Returns:
//   - *yaml.Node: the value, or nil when the mapping does not hold key.
func mappingValue(node *yaml.Node, key string) *yaml.Node {
	if node.Kind != yaml.MappingNode {
		return nil
	}

	for index := 0; index+1 < len(node.Content); index += 2 {
		if node.Content[index].Value == key {
			return node.Content[index+1]
		}
	}

	return nil
}
