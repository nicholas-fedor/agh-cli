// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package prompt reads operator input from a command's standard streams.
//
// It reads a secret without echoing it when the input is a terminal, reads it
// whole when the input is redirected, and asks for a confirmation that only a
// terminal can answer. A secret is returned to the caller and is never written,
// logged, or reported.
package prompt
