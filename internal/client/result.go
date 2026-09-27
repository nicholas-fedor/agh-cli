// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

// Row is one configured or automatically discovered client in a list result.
type Row struct {
	// Name is the client name reported by AdGuard Home.
	Name string
	// Automatic reports whether the client was discovered rather than configured.
	Automatic bool
}

// Result contains the display-oriented rows returned for one instance.
type Result struct {
	// Rows contains configured clients before automatically discovered clients.
	Rows []Row
}
