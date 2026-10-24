// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"slices"

	"github.com/spf13/pflag"

	"github.com/nicholas-fedor/agh-cli/internal/client"
)

// ClientMutationFlags stores the flags of the client add and update commands.
type ClientMutationFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// IDs holds the --id flag values.
	IDs []string
	// UseGlobal holds the --use-global flag value.
	UseGlobal bool
	// Filtering holds the --filtering flag value.
	Filtering bool
	// Parental holds the --parental flag value.
	Parental bool
	// Safebrowsing holds the --safebrowsing flag value.
	Safebrowsing bool
}

// Bind registers the client settings and instance-selection flags and binds
// their values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the client mutation flags.
func (f *ClientMutationFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&f.UseGlobal, "use-global", "g", true, "use global settings")
	flags.BoolVarP(&f.Filtering, "filtering", "f", false, "enable filtering")
	flags.BoolVarP(&f.Parental, "parental", "p", false, "enable parental control")
	flags.BoolVarP(&f.Safebrowsing, "safebrowsing", "s", false, "enable safebrowsing")
	flags.StringArrayVarP(&f.IDs, "id", "I", []string{}, "client IDs (IP, CIDR, MAC, or ClientID)")
	f.InstanceSelection.Bind(flags)
}

// Settings returns the client values the flags describe.
//
// Parameters:
//   - name: name of the client to add or update.
//
// Returns:
//   - [client.Settings]: the client values sent to every selected instance.
func (f *ClientMutationFlags) Settings(name string) client.Settings {
	return client.Settings{
		Name:                name,
		IDs:                 slices.Clone(f.IDs),
		UseGlobalSettings:   f.UseGlobal,
		FilteringEnabled:    f.Filtering,
		ParentalEnabled:     f.Parental,
		SafebrowsingEnabled: f.Safebrowsing,
	}
}
