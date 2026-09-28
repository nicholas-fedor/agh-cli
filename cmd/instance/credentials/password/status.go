// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// statusValues stores the flag values bound to one status command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type statusValues struct {
	// json holds the --json flag value.
	json bool
}

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
func presenceLabel(presence app.Presence) string {
	switch presence {
	case app.PresencePresent:
		return "present"
	case app.PresenceAbsent:
		return "absent"
	default:
		return "unknown"
	}
}

// newStatusCommand creates the password status command and binds its flags.
//
// The command reports presence only. There is intentionally no command that
// prints a stored secret, so an operator can inspect an instance safely in a
// shared terminal or a captured log.
//
// Parameters:
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The status command with its own flag values.
func newStatusCommand(seams *streams) *cobra.Command {
	values := &statusValues{}

	command := &cobra.Command{
		Use:   "status [instance]",
		Short: "Report stored credential presence",
		Long: `Report the credential store backend, its availability, and the
configured credential source and presence of one instance, or of every
configured instance. A stored secret is never reported.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runStatus(cmd, args, values, seams)
		},
	}

	command.Flags().BoolVar(
		&values.json,
		jsonFlagName,
		false,
		"render the report as JSON",
	)

	return command
}

// runStatus reports credential presence for the selected instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: an optional instance name.
//   - values: Bound flag values selecting the output format.
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - error: a wrapped error when the coordinator cannot be built, an instance
//     is unknown, or the report cannot be written.
func runStatus(cmd *cobra.Command, args []string, values *statusValues, seams *streams) error {
	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	result, err := store.StatusPassword(cmd.Context(), selectedNames(args))
	if err != nil {
		return fmt.Errorf("report credential status: %w", err)
	}

	if values.json {
		err = writeStatusJSON(cmd.OutOrStdout(), result)
	} else {
		err = writeStatusText(cmd.OutOrStdout(), result)
	}

	if err != nil {
		return fmt.Errorf("write credential status: %w", err)
	}

	return nil
}

// selectedNames returns the instance names inspected by a status report.
//
// An empty result means every configured instance, which matches the use case
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

// writeStatusText renders the human-readable status report.
//
// Parameters:
//   - out: destination for the report.
//   - result: credential status report.
//
// Returns:
//   - error: a wrapped error when the report cannot be written.
func writeStatusText(out io.Writer, result app.PasswordReport) error {
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

	_, err := fmt.Fprintln(out, strings.Join(lines, "\n"))
	if err != nil {
		return fmt.Errorf("write credential status: %w", err)
	}

	return nil
}

// passwordLine renders one instance credential state.
//
// Parameters:
//   - entry: reported state of one instance credential.
//
// Returns:
//   - string: the rendered line.
func passwordLine(entry app.PasswordStatus) string {
	line := "instance " + strconv.Quote(entry.Instance) + ": source " + string(entry.Source)

	if target := entry.TargetLabel(); target != "" {
		line += ", " + target
	}

	line += ", " + presenceLabel(entry.Presence)

	if entry.Err != nil {
		line += ": " + entry.Err.Error()
	}

	return line
}

// writeStatusJSON renders the machine-readable status report.
//
// The report carries configuration state and presence only, so writing it can
// never disclose a secret.
//
// Parameters:
//   - out: destination for the report.
//   - result: credential status report.
//
// Returns:
//   - error: a wrapped error when the report cannot be encoded or written.
func writeStatusJSON(out io.Writer, result app.PasswordReport) error {
	encoder := json.NewEncoder(out)
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

// passwordEntries converts the reported states into the machine-readable shape.
//
// Parameters:
//   - states: reported states in configuration order.
//
// Returns:
//   - []passwordEntry: one entry per reported state in the same order.
func passwordEntries(states []app.PasswordStatus) []passwordEntry {
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
