// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package credentials provides the Cobra commands that manage the operating
// system credential store entries backing AdGuard Home instances.
//
// The package owns presentation and secret input only. A secret is read from a
// hidden terminal prompt or from standard input, is handed to
// [github.com/nicholas-fedor/agh-cli/internal/app.Credentials], and is never
// echoed, logged, returned, or written to an output stream. There is
// intentionally no command that prints a stored secret.
//
// The package depends on [github.com/nicholas-fedor/agh-cli/internal/app],
// Cobra, and the terminal reader. It never imports the credential store
// adapter or the configuration package, so credential policy and persistence
// stay in the application layer.
package credentials
