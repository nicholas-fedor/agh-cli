// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"github.com/spf13/pflag"
)

// FilteringAddURLFlags stores the flags of the filtering add-url command.
type FilteringAddURLFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// Whitelist holds the --whitelist flag value.
	Whitelist bool
}

// FilteringConfigFlags stores the flags of the filtering config command.
type FilteringConfigFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// Enabled holds the --enabled flag value.
	Enabled bool
	// Interval holds the --interval flag value in hours.
	Interval int32
}

// Bind registers the allowlist and instance-selection flags and binds their
// values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the add-url flags.
func (f *FilteringAddURLFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&f.Whitelist, "whitelist", "w", false, "add to whitelist")
	f.InstanceSelection.Bind(flags)
}

// Bind registers the filtering configuration and instance-selection flags and
// binds their values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the config flags.
func (f *FilteringConfigFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&f.Enabled, "enabled", "e", true, "enable filtering")
	flags.Int32VarP(&f.Interval, "interval", "n", 0, "update interval hours")
	f.InstanceSelection.Bind(flags)
}

// IntervalHours returns the update interval in the width the use case takes.
//
// Returns:
//   - int64: the --interval flag value in hours.
func (f *FilteringConfigFlags) IntervalHours() int64 {
	return int64(f.Interval)
}
