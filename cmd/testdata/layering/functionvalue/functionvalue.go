// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package functionvalue keeps a domain constructor as a value, which the
// layering test refuses.
package functionvalue

import "github.com/nicholas-fedor/agh-cli/internal/credentials"

// newManager holds the domain constructor to call it later.
var newManager = credentials.NewManager

// manager builds a manager through the stored constructor.
func manager() *credentials.Manager {
	return newManager(nil, nil)
}
