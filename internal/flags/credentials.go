// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"
)

// ReportFlags stores the flag of a credential status command.
type ReportFlags struct {
	// JSON holds the --json flag value.
	JSON bool
}

// MigrateFlags stores the flag of the credentials migrate command.
type MigrateFlags struct {
	// DryRun holds the --dry-run flag value.
	DryRun bool
}

// PasswordSetFlags stores the flags of the password set command.
type PasswordSetFlags struct {
	// Key holds the --key flag value.
	Key string
	// Yes holds the --yes flag value.
	Yes bool
}

// PasswordClearFlags stores the flags of the password clear command.
type PasswordClearFlags struct {
	// All holds the --all flag value.
	All bool
	// Yes holds the --yes flag value.
	Yes bool
}

// ErrInvalidSelection reports a clear request naming an instance while asking for
// every credential, or naming neither.
var ErrInvalidSelection = errors.New("specify an instance name or --all")

// Bind registers the --json flag and binds its value to the receiver.
//
// Parameters:
//   - flags: flag set that receives the report flag.
func (f *ReportFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVar(&f.JSON, "json", false, "render the report as JSON")
}

// Bind registers the --dry-run flag and binds its value to the receiver.
//
// Parameters:
//   - flags: flag set that receives the migrate flag.
func (f *MigrateFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVar(
		&f.DryRun,
		"dry-run",
		false,
		"report the change without writing to the store or the configuration",
	)
}

// Bind registers the --key and --yes flags and binds their values to the
// receiver.
//
// Parameters:
//   - flags: flag set that receives the set flags.
func (f *PasswordSetFlags) Bind(flags *pflag.FlagSet) {
	flags.StringVar(&f.Key, "key", "", "credential key, defaults to the instance name")
	flags.BoolVarP(&f.Yes, "yes", "y", false, "store the credential without asking for confirmation")
}

// Bind registers the --all and --yes flags and binds their values to the
// receiver.
//
// Parameters:
//   - flags: flag set that receives the clear flags.
func (f *PasswordClearFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVar(&f.All, "all", false, "remove every credential of the configured service")
	flags.BoolVarP(&f.Yes, "yes", "y", false, "remove the credential without asking for confirmation")
}

// Validate refuses a selection that names an instance and the whole service, or
// neither.
//
// Parameters:
//   - args: positional arguments, optionally naming one instance.
//
// Returns:
//   - error: an error wrapping [ErrInvalidSelection] when the selection is
//     ambiguous or empty.
func (f *PasswordClearFlags) Validate(args []string) error {
	if f.All && len(args) > 0 {
		return fmt.Errorf("%w: --all and an instance name are mutually exclusive", ErrInvalidSelection)
	}

	if !f.All && len(args) == 0 {
		return ErrInvalidSelection
	}

	return nil
}
