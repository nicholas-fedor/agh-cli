// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package method calls a method on a domain value, which the layering test
// refuses.
package method

import (
	"context"

	"github.com/nicholas-fedor/agh-cli/internal/client"
)

// list calls into the client domain through a method of its service.
func list(ctx context.Context, service *client.Service) error {
	_, err := service.List(ctx)

	return err
}
