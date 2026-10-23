// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package pointerconversion converts to a pointer to a domain type, which the
// layering test refuses.
package pointerconversion

import "github.com/nicholas-fedor/agh-cli/internal/client"

// convert converts a settings pointer through the domain type.
func convert(settings *client.Settings) *client.Settings {
	return (*client.Settings)(settings)
}
