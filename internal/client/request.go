// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

// AddRequest contains the values used to add a configured client.
type AddRequest struct {
	// Name is the client name reported by AdGuard Home.
	Name string
	// IDs contains the identifiers associated with the client name.
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

// UpdateRequest contains the values used to update a configured client.
type UpdateRequest struct {
	// Name identifies the configured client to patch.
	Name string
	// IDs contains the identifiers set when the request supplies any.
	IDs []string
	// UseGlobalSettings is the patched global-settings state.
	UseGlobalSettings bool
	// FilteringEnabled is the patched per-client filtering state.
	FilteringEnabled bool
	// ParentalEnabled is the patched parental-control state.
	ParentalEnabled bool
	// SafebrowsingEnabled is the patched safe-browsing filter state.
	SafebrowsingEnabled bool
}
