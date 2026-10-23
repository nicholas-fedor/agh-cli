// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package connection builds AdGuard Home API clients for configured instances.
//
// One constructor turns a validated instance configuration into a client, so
// every feature reaches an instance with the same base URL, authentication, and
// request timeout.
package connection
