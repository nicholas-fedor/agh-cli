// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
)

// UpdateService exposes AdGuard Home server update operations.
type UpdateService interface {
	BeginUpdate(ctx context.Context) error
}

// operationBeginUpdate identifies BeginUpdate errors.
const operationBeginUpdate = "begin_update"

var _ UpdateService = (*Client)(nil)

// BeginUpdate begins the AdGuard Home auto-upgrade procedure.
//
// BeginUpdate sends a bodyless POST to /control/update. Any 2xx response is
// accepted, including an empty response. The response is bounded, redirects are
// rejected, and the caller's context and configured request timeout bound the
// complete operation.
//
// Parameters:
//   - ctx: The request context. Cancellation stops the request.
//
// Returns:
//   - err: An [Error] for request, redirect, HTTP, response-limit, or
//     response-body failures; otherwise nil.
func (c *Client) BeginUpdate(ctx context.Context) error {
	requestErr := c.postNoContent(ctx, operationBeginUpdate, "control/update")
	if requestErr != nil {
		return requestErr
	}

	return nil
}
