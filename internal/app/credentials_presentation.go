// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"strconv"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TargetLabel describes the configured credential identity of one instance.
//
// The label names the field the configured source reads, so a keyring key, a
// mounted-secret path, and an environment variable name are never confused in
// command output. A source that owns no identity, such as the legacy plaintext
// password and the unauthenticated source, has no label.
//
// The identity is configuration rather than a secret, so rendering it discloses
// nothing. This method exists so the command layer never names a credential
// source itself and therefore never depends on the instance domain package.
//
// Returns:
//   - string: the field name followed by the quoted identity, or an empty string
//     when the configured source owns no identity.
func (status CredentialStatus) TargetLabel() string {
	switch status.Source {
	case instance.KeyringSource:
		return "key " + strconv.Quote(status.Target)
	case instance.FileSource:
		return "path " + strconv.Quote(status.Target)
	case instance.EnvSource:
		return "variable " + strconv.Quote(status.Target)
	default:
		// The legacy plaintext password and the unauthenticated source own no
		// credential identity, and an unsupported source is reported by its
		// configuration alone.
		return ""
	}
}
