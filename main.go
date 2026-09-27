// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the agh-cli entrypoint for managing
// multiple AdGuard Home instances.
package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/nicholas-fedor/agh-cli/cmd"
)

// main is the CLI entrypoint. It executes the root Cobra command and
// terminates the process on error.
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	err := cmd.ExecuteContext(ctx)

	stop()

	if err != nil {
		log.Fatalf("CLI execution failed: %v", err)
	}
}
