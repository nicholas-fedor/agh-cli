// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package values names domain values the way the command layer may.
package values

import (
	"github.com/nicholas-fedor/agh-cli/internal/client"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// status builds and reads a domain value.
var status = credentials.PasswordStatus{TargetKind: "key", Presence: credentials.PresencePresent}

// settings builds a domain request.
var settings = client.Settings{Name: status.Target}

// refused names a domain sentinel error.
var refused = credentials.ErrExternalCredentialSource
