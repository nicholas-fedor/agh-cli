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

// usernameEntry is the machine-readable form of one instance username.
type usernameEntry struct {
	// Instance is the inspected instance name.
	Instance string `json:"instance"`
	// Username is the configured administrator username. It is empty when no
	// username is configured.
	Username string `json:"username,omitempty"`
}

// usernameReport is the machine-readable username report document.
type usernameReport struct {
	// Instances contains one entry per inspected instance in configuration order.
	Instances []usernameEntry `json:"instances"`
}

// unsetLabel is rendered for an instance with no configured username, so an
// empty value is never mistaken for a configured empty identity.
const unsetLabel = "(unset)"

// WriteUsernameStatusText writes the human-readable username report.
//
// Parameters:
//   - writer: destination for the report.
//   - report: username report.
//
// Returns:
//   - error: a wrapped error when the report cannot be written.
func WriteUsernameStatusText(writer io.Writer, report credentials.UsernameReport) error {
	lines := make([]string, 0, len(report.Instances))

	for _, entry := range report.Instances {
		lines = append(lines, usernameLine(entry))
	}

	_, err := fmt.Fprintln(writer, strings.Join(lines, "\n"))
	if err != nil {
		return fmt.Errorf("write username status: %w", err)
	}

	return nil
}

// WriteUsernameStatusJSON writes the machine-readable username report.
//
// The report carries configuration only, so writing it can never disclose a
// secret.
//
// Parameters:
//   - writer: destination for the report.
//   - report: username report.
//
// Returns:
//   - error: a wrapped error when the report cannot be encoded or written.
func WriteUsernameStatusJSON(writer io.Writer, report credentials.UsernameReport) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(usernameReport{Instances: usernameEntries(report.Instances)})
	if err != nil {
		return fmt.Errorf("encode username status: %w", err)
	}

	return nil
}

// WriteUsernameSet writes the outcome of a recorded username.
//
// Parameters:
//   - writer: destination for the outcome.
//   - name: instance name.
//   - username: recorded administrator username.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WriteUsernameSet(writer io.Writer, name, username string) error {
	_, err := fmt.Fprintf(writer, "Username for instance %q set to %s.\n", name, strconv.Quote(username))
	if err != nil {
		return fmt.Errorf("write username outcome: %w", err)
	}

	return nil
}

// WriteUsernameCleared writes the outcome of a removed username.
//
// Parameters:
//   - writer: destination for the outcome.
//   - name: instance name.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WriteUsernameCleared(writer io.Writer, name string) error {
	_, err := fmt.Fprintf(writer, "Username for instance %q cleared.\n", name)
	if err != nil {
		return fmt.Errorf("write username outcome: %w", err)
	}

	return nil
}

// usernameLine renders one instance username.
//
// Parameters:
//   - entry: reported username of one instance.
//
// Returns:
//   - string: the rendered line.
func usernameLine(entry credentials.UsernameStatus) string {
	if entry.Username == "" {
		return "instance " + strconv.Quote(entry.Instance) + ": " + unsetLabel
	}

	return "instance " + strconv.Quote(entry.Instance) + ": username " + strconv.Quote(entry.Username)
}

// usernameEntries converts the reported usernames into the machine-readable
// shape.
//
// Parameters:
//   - states: reported usernames in configuration order.
//
// Returns:
//   - []usernameEntry: one entry per reported username in the same order.
func usernameEntries(states []credentials.UsernameStatus) []usernameEntry {
	entries := make([]usernameEntry, 0, len(states))

	for _, state := range states {
		entries = append(entries, usernameEntry{Instance: state.Instance, Username: state.Username})
	}

	return entries
}
