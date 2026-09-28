// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package username

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// statusValues stores the flag values bound to the status command.
type statusValues struct {
	// asJSON renders the machine-readable report.
	asJSON bool
}

// statusEntry is the machine-readable form of one instance username.
type statusEntry struct {
	// Instance is the inspected instance name.
	Instance string `json:"instance"`
	// Username is the configured administrator username. It is empty when no
	// username is configured.
	Username string `json:"username,omitempty"`
}

// statusReport is the machine-readable username report document.
type statusReport struct {
	// Instances contains one entry per inspected instance in configuration order.
	Instances []statusEntry `json:"instances"`
}

// unsetLabel is rendered for an instance with no configured username, so an
// empty value is never mistaken for a configured empty identity.
const unsetLabel = "(unset)"

// newStatusCommand creates the username status command.
//
// Parameters:
//   - seams: credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The status command.
func newStatusCommand(seams *streams) *cobra.Command {
	values := &statusValues{}

	command := &cobra.Command{
		Use:   "status [instance]",
		Short: "Report the administrator username of a configured instance",
		Long: `Report the configured AdGuard Home administrator username. With no
argument every configured instance is reported in configuration order.
A username is configuration rather than a secret, so reporting it is
safe; use 'agh-cli instance credentials password status' for the password
side.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, args, values, seams)
		},
	}

	command.Flags().BoolVar(&values.asJSON, jsonFlagName, false, "render the report as JSON")

	return command
}

// runStatus reports the configured username of the selected instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: an optional instance name.
//   - values: Bound flag values selecting the output format.
//   - seams: credential coordinator factory.
//
// Returns:
//   - error: a wrapped error when the coordinator cannot be built, an instance is
//     unknown, or the report cannot be written.
func runStatus(cmd *cobra.Command, args []string, values *statusValues, seams *streams) error {
	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	report, err := store.StatusUsername(selectedNames(args))
	if err != nil {
		return fmt.Errorf("report username status: %w", err)
	}

	if values.asJSON {
		err = writeStatusJSON(cmd.OutOrStdout(), report)
	} else {
		err = writeStatusText(cmd.OutOrStdout(), report)
	}

	if err != nil {
		return fmt.Errorf("write username status: %w", err)
	}

	return nil
}

// selectedNames returns the instance names inspected by a status report.
//
// An empty result means every configured instance, which matches the use-case
// contract, so the command passes the names through unchanged.
//
// Parameters:
//   - args: positional arguments, optionally naming one instance.
//
// Returns:
//   - []string: the inspected instance names.
func selectedNames(args []string) []string {
	if len(args) == 0 {
		return nil
	}

	return args
}

// writeStatusText renders the human-readable username report.
//
// Parameters:
//   - out: destination for the report.
//   - report: username report.
//
// Returns:
//   - error: a wrapped error when the report cannot be written.
func writeStatusText(out io.Writer, report app.UsernameReport) error {
	lines := make([]string, 0, len(report.Instances))

	for _, entry := range report.Instances {
		lines = append(lines, statusLine(entry))
	}

	_, err := fmt.Fprintln(out, strings.Join(lines, "\n"))
	if err != nil {
		return fmt.Errorf("write username status: %w", err)
	}

	return nil
}

// statusLine renders one instance username.
//
// Parameters:
//   - entry: reported username of one instance.
//
// Returns:
//   - string: the rendered line.
func statusLine(entry app.UsernameStatus) string {
	if entry.Username == "" {
		return "instance " + strconv.Quote(entry.Instance) + ": " + unsetLabel
	}

	return "instance " + strconv.Quote(entry.Instance) +
		": username " + strconv.Quote(entry.Username)
}

// writeStatusJSON renders the machine-readable username report.
//
// The report carries configuration only, so writing it can never disclose a
// secret.
//
// Parameters:
//   - out: destination for the report.
//   - report: username report.
//
// Returns:
//   - error: a wrapped error when the report cannot be encoded or written.
func writeStatusJSON(out io.Writer, report app.UsernameReport) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")

	err := encoder.Encode(statusReport{Instances: statusEntries(report.Instances)})
	if err != nil {
		return fmt.Errorf("encode username status: %w", err)
	}

	return nil
}

// statusEntries converts the reported usernames into the machine-readable shape.
//
// Parameters:
//   - states: reported usernames in configuration order.
//
// Returns:
//   - []statusEntry: one entry per reported username in the same order.
func statusEntries(states []app.UsernameStatus) []statusEntry {
	entries := make([]statusEntry, 0, len(states))

	for _, state := range states {
		entries = append(entries, statusEntry{
			Instance: state.Instance,
			Username: state.Username,
		})
	}

	return entries
}
