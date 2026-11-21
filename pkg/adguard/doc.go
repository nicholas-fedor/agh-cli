// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package adguard provides a small, project-owned client for the AdGuard Home
// v1 HTTP API.
//
// The package owns transport policy, authentication, response limits, strict
// JSON decoding, and domain models. Callers provide a server base URL and may
// inject an HTTP client for custom transports, proxies, or observability.
package adguard
