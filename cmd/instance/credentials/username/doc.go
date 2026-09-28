// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package username provides the Cobra commands that manage the AdGuard Home
// administrator username of a configured instance.
//
// A username is configuration rather than a secret. It lives in the
// configuration file, is never written to the credential store, and is accepted
// as an ordinary argument because it is safe in a process listing and in shell
// history. The package owns presentation only and hands every change to
// [github.com/nicholas-fedor/agh-cli/internal/app.Credentials].
//
// The package never reads a secret and never prompts, because no command here
// touches a password. Password management lives in the sibling password package.
package username
