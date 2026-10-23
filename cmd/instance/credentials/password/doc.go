// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package password provides the Cobra commands that manage the AdGuard Home
// administrator password of a configured instance.
//
// The password is a secret. It is read from a hidden terminal prompt or from
// standard input, is handed to
// [github.com/nicholas-fedor/agh-cli/internal/credentials.Manager], and is never
// echoed, logged, returned, or written to an output stream. There is
// intentionally no command that prints a stored password, and no flag that
// accepts one as an argument.
//
// The package owns presentation and secret input only. It names the report and
// result types of the credential package but never calls into it, and it never
// imports the configuration package, so credential policy and persistence stay
// behind the application layer. The configured username is
// managed in the sibling username package.
package password
