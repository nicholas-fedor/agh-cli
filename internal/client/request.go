// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

// Settings contains the values sent for one configured client, both when it is
// added and when it is updated.
type Settings struct {
	// Name is the client name reported by AdGuard Home. An update uses it to
	// identify the client it patches.
	Name string
	// IDs contains the identifiers associated with the client name. An update
	// that supplies none leaves the configured identifiers in place.
	IDs []string
	// UseGlobalSettings reports whether global client settings are inherited.
	UseGlobalSettings bool
	// FilteringEnabled reports whether per-client filtering is enabled.
	FilteringEnabled bool
	// ParentalEnabled reports whether the parental control is enabled.
	ParentalEnabled bool
	// SafebrowsingEnabled reports whether the safe-browsing filter is enabled.
	SafebrowsingEnabled bool
}

// DeleteRequest identifies a configured client to delete.
type DeleteRequest struct {
	// Name is the client name to remove.
	Name string
}
