// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package flags defines the flag containers of the commands and their pflag
// bindings.
//
// Each command binds one container to its own flag set, so repeated command
// construction never shares flag state. A container also checks the values
// Cobra cannot check on its own, and it turns them into the requests and the
// instance selection the application layer takes.
package flags
