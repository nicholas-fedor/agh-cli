// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package credentials owns AdGuard Home credential storage and resolution.
//
// The package stores secrets in the operating system credential store, reads
// externally managed secrets from read-only mounted files and environment
// variables, and resolves the credential source configured for an instance. A
// configured source is the only source that is read, so a failed lookup never
// falls back to another source, the legacy plaintext password, or a different
// credential identity.
//
// A secret never appears in an error, a status value, or any other value the
// package returns. Errors carry the service, the credential key, the file path,
// or the environment variable name, all of which are configuration rather than
// secret material.
package credentials
