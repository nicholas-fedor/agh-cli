// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"slices"

	"github.com/spf13/pflag"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// InstanceSelection stores the instance-selection flags shared by every command
// that runs against configured instances.
type InstanceSelection struct {
	// Names holds the --instance flag values.
	Names []string
	// All holds the --all flag value.
	All bool
}

// Bind registers the --all and --instance flags and binds their values to the
// receiver.
//
// Parameters:
//   - flags: flag set that receives the selection flags.
func (s *InstanceSelection) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&s.All, "all", "a", false, "target all instances")
	flags.StringSliceVarP(&s.Names, "instance", "i", []string{}, "target instance name(s)")
}

// Selection returns the instance selection the operator asked for.
//
// Returns:
//   - [app.Selection]: the selected names and the --all choice.
func (s *InstanceSelection) Selection() app.Selection {
	return app.Selection{
		Names: slices.Clone(s.Names),
		All:   s.All,
	}
}
