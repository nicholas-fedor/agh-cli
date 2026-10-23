// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package dotimport dot-imports a domain package, which the layering test
// refuses.
package dotimport

import . "github.com/nicholas-fedor/agh-cli/internal/credentials"

// refused names a domain value without its package name.
var refused = ErrExternalCredentialSource
