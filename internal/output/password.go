// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// passwordEntry is the machine-readable state of one instance credential.
//
// The entry describes configuration and presence only. It never carries a
// secret, and it never carries a value derived from one.
type passwordEntry struct {
	// Instance is the instance name whose password was inspected.
	Instance string `json:"instance"`
	// Source is the configured credential source.
	Source string `json:"source"`
	// Target names the configured credential identity, such as a keyring key, a
	// mounted-secret path, or an environment variable name. It is empty for a
	// source that owns no identity.
	Target string `json:"target,omitempty"`
	// Presence reports how the configured source currently supplies a password.
	Presence string `json:"presence"`
	// Error explains why presence is unknown. It is empty when the store
	// answered the read.
	Error string `json:"error,omitempty"`
}

// passwordReport is the machine-readable credential status document.
type passwordReport struct {
	// Backend is the credential store backend name.
	Backend string `json:"backend"`
	// Service is the credential store namespace.
	Service string `json:"service"`
	// Available reports whether every credential store read succeeded.
	Available bool `json:"available"`
	// Instances contains one entry per inspected instance in configuration
	// order.
	Instances []passwordEntry `json:"instances"`
}

// WritePasswordStatusText writes the human-readable credential status report.
//
// Parameters:
//   - writer: destination for the report.
//   - result: credential status report.
//
// Returns:
//   - error: a wrapped error when the report cannot be written.
func WritePasswordStatusText(writer io.Writer, result credentials.PasswordReport) error {
	lines := make([]string, 0, 3+len(result.Instances))

	lines = append(
		lines,
		"backend: "+result.Backend,
		"service: "+result.Service,
		"available: "+strconv.FormatBool(result.Available),
	)

	for _, entry := range result.Instances {
		lines = append(lines, passwordLine(entry))
	}

	_, err := fmt.Fprintln(writer, strings.Join(lines, "\n"))
	if err != nil {
		return fmt.Errorf("write credential status: %w", err)
	}

	return nil
}

// WritePasswordStatusJSON writes the machine-readable credential status report.
//
// The report carries configuration state and presence only, so writing it can
// never disclose a secret.
//
// Parameters:
//   - writer: destination for the report.
//   - result: credential status report.
//
// Returns:
//   - error: a wrapped error when the report cannot be encoded or written.
func WritePasswordStatusJSON(writer io.Writer, result credentials.PasswordReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(passwordReport{
		Backend:   result.Backend,
		Service:   result.Service,
		Available: result.Available,
		Instances: passwordEntries(result.Instances),
	})
	if err != nil {
		return fmt.Errorf("encode credential status: %w", err)
	}

	return nil
}

// WritePasswordSet writes the outcome of a stored credential.
//
// Only configuration state is reported. The secret, and any value derived from
// it, never reaches an output stream. A configuration file that still holds the
// plaintext password is reported as a warning on the error stream.
//
// Parameters:
//   - writer: destination for the outcome.
//   - errWriter: destination for the warning.
//   - result: outcome of the credential write.
//
// Returns:
//   - error: a wrapped error when the outcome or the warning cannot be written.
func WritePasswordSet(writer, errWriter io.Writer, result credentials.PasswordSetResult) error {
	action := "Stored"
	if result.Replaced {
		action = "Replaced"
	}

	_, err := fmt.Fprintf(
		writer,
		"%s credential for instance %q in %s service %q with key %q.\n",
		action,
		result.Instance,
		result.Backend,
		result.Service,
		result.Key,
	)
	if err != nil {
		return fmt.Errorf("write credential outcome: %w", err)
	}

	if result.Saved {
		return nil
	}

	_, err = fmt.Fprintf(
		errWriter,
		"Warning: the credential was stored, but the configuration file still "+
			"holds the plaintext password for instance %q. Run the command again.\n",
		result.Instance,
	)
	if err != nil {
		return fmt.Errorf("write credential warning: %w", err)
	}

	return nil
}

// WritePasswordClear writes the outcome of one cleared credential.
//
// A deleted credential that the configuration file still references is
// reported as a warning on the error stream, so the operator knows what to
// repeat.
//
// Parameters:
//   - writer: destination for the outcome.
//   - errWriter: destination for the warning.
//   - result: outcome of the credential delete.
//
// Returns:
//   - error: a wrapped error when the outcome or the warning cannot be written.
func WritePasswordClear(writer, errWriter io.Writer, result credentials.PasswordClearResult) error {
	var err error

	switch {
	case result.Shared:
		_, err = fmt.Fprintf(
			writer,
			"Kept credential with key %q in service %q: another configured "+
				"instance still reads its password through it.\n",
			result.Key,
			result.Service,
		)
	case !result.Removed:
		_, err = fmt.Fprintf(
			writer,
			"No stored credential for instance %q with key %q in service %q.\n",
			result.Instance,
			result.Key,
			result.Service,
		)
	default:
		_, err = fmt.Fprintf(
			writer,
			"Removed credential for instance %q with key %q from service %q.\n",
			result.Instance,
			result.Key,
			result.Service,
		)
		if err == nil {
			err = writeUnsavedReference(errWriter, result)
		}
	}

	if err != nil {
		return fmt.Errorf("write credential outcome: %w", err)
	}

	return nil
}

// WritePasswordClearAll writes the outcome of a service-wide clear.
//
// Parameters:
//   - writer: destination for the outcome.
//   - result: outcome of the service-wide delete.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WritePasswordClearAll(writer io.Writer, result credentials.PasswordClearResult) error {
	_, err := fmt.Fprintf(writer, "Removed every credential in service %q.\n", result.Service)
	if err != nil {
		return fmt.Errorf("write credential outcome: %w", err)
	}

	return nil
}

// writeUnsavedReference warns that a deleted credential is still referenced by
// the configuration file.
//
// Parameters:
//   - errWriter: destination for the warning.
//   - result: outcome of the credential delete.
//
// Returns:
//   - error: the write error, or nil when the reference was saved.
func writeUnsavedReference(errWriter io.Writer, result credentials.PasswordClearResult) error {
	if result.Saved {
		return nil
	}

	_, err := fmt.Fprintf(
		errWriter,
		"Warning: the credential was removed, but instance %q still references it "+
			"in the configuration file. Run the command again.\n",
		result.Instance,
	)
	if err != nil {
		return fmt.Errorf("write unsaved reference warning: %w", err)
	}

	return nil
}

// presenceLabel renders one presence value for display.
//
// An unexpected presence value is reported as unknown, because reporting a
// value the store did not state would overstate what agh-cli knows.
//
// Parameters:
//   - presence: reported presence.
//
// Returns:
//   - string: the label shown in output.
func presenceLabel(presence credentials.Presence) string {
	switch presence {
	case credentials.PresencePresent:
		return "present"
	case credentials.PresenceAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// passwordLine renders one instance credential state.
//
// Parameters:
//   - entry: reported state of one instance credential.
//
// Returns:
//   - string: the rendered line.
func passwordLine(entry credentials.PasswordStatus) string {
	line := "instance " + strconv.Quote(entry.Instance) + ": source " + string(entry.Source)

	if entry.TargetKind != "" {
		line += ", " + entry.TargetKind + " " + strconv.Quote(entry.Target)
	}

	line += ", " + presenceLabel(entry.Presence)

	if entry.Err != nil {
		line += ": " + entry.Err.Error()
	}

	return line
}

// passwordEntries converts the reported states into the machine-readable shape.
//
// Parameters:
//   - states: reported states in configuration order.
//
// Returns:
//   - []passwordEntry: one entry per reported state in the same order.
func passwordEntries(states []credentials.PasswordStatus) []passwordEntry {
	entries := make([]passwordEntry, 0, len(states))

	for _, state := range states {
		entries = append(entries, passwordEntry{
			Instance: state.Instance,
			Source:   string(state.Source),
			Target:   state.Target,
			Presence: presenceLabel(state.Presence),
			Error:    errorText(state.Err),
		})
	}

	return entries
}

// errorText renders an optional error.
//
// Parameters:
//   - err: reported error, or nil.
//
// Returns:
//   - string: the error message, or an empty string when there is no error.
func errorText(err error) string {
	if err == nil {
		return ""
	}

	return err.Error()
}
