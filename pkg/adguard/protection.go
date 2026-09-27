// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"net/http"
)

// ProtectionConfig configures AdGuard Home protection.
type ProtectionConfig struct {
	// Enabled selects whether protection is enabled. The value is always sent,
	// including an explicit false value.
	Enabled bool
	// Duration optionally sets the protection pause duration. Nil omits the
	// field, while a nonnil pointer sends an explicit value, including zero.
	Duration *uint64
}

// protectionConfigWire mirrors the pinned protection request contract.
type protectionConfigWire struct {
	Enabled  bool    `json:"enabled"`
	Duration *uint64 `json:"duration,omitempty"`
}

const (
	// OperationSetProtection identifies protection updates.
	operationSetProtection = "set_protection"
	// OperationClearCache identifies DNS cache clearing.
	operationClearCache = "clear_cache"
)

// SetProtection changes the global protection state.
//
// A nil Duration omits the pause duration, while a nonnil pointer sends its
// value explicitly, including zero.
//
// Parameters:
//   - ctx: The request context.
//   - config: The protection state and optional pause duration.
//
// Returns:
//   - An error when the bounded request cannot be completed.
func (c *Client) SetProtection(ctx context.Context, config ProtectionConfig) error {
	requestErr := c.postEmpty(
		ctx,
		operationSetProtection,
		http.MethodPost,
		"control/protection",
		protectionConfigWire(config),
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// ClearCache clears the DNS response cache.
//
// Parameters:
//   - ctx: The request context.
//
// Returns:
//   - An error when the bodyless request or bounded response cannot be completed.
func (c *Client) ClearCache(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, operationClearCache, "control/cache_clear")
	if requestErr != nil {
		return requestErr
	}

	return nil
}
