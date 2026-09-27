// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metadata provides application version and build information.
// It derives the version from Go build information and supports build-time
// values for commit and timestamp metadata.
//
// # Usage
//
//	import (
//		"fmt"
//
//		"github.com/nicholas-fedor/agh-cli/internal/metadata"
//	)
//
//	fmt.Printf("%s %s\n", metadata.Name, metadata.String())
//	info := metadata.GetInfo() // Structured data for JSON or other output.
//
// # Build-time Injection
//
// To set Version, CommitSHA, and BuildTime at build time, use ldflags:
//
//	go build -ldflags "-X 'github.com/nicholas-fedor/agh-cli/internal/metadata.Version=v1.0.0' \
//		-X 'github.com/nicholas-fedor/agh-cli/internal/metadata.CommitSHA=abc123' \
//		-X 'github.com/nicholas-fedor/agh-cli/internal/metadata.BuildTime=2025-01-15T12:00:00Z'"
package metadata
