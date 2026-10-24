// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"github.com/spf13/pflag"
)

// InstanceListFlags stores the flags of the instance list command.
type InstanceListFlags struct {
	// All holds the --all flag value.
	All bool
}

// InstanceAddFlags stores the flags of the instance add command.
type InstanceAddFlags struct {
	// Scheme holds the --scheme flag value.
	Scheme string
}

// Bind registers the --all flag and binds its value to the receiver.
//
// Parameters:
//   - flags: flag set that receives the list flags.
func (f *InstanceListFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&f.All, "all", "a", false, "show all instances")
}

// Bind registers the --scheme flag and binds its value to the receiver.
//
// Parameters:
//   - flags: flag set that receives the add flags.
func (f *InstanceAddFlags) Bind(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Scheme, "scheme", "s", "https", "HTTP scheme")
}
