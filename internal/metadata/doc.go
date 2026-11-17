// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package metadata provides application version and build information.
//
// A build injects the version, commit, and timestamp with ldflags. An injected
// version is always the one reported. A build that injects no version reports
// the main module version from the Go build information, such as the version
// go install records for a tagged module. Without either, the version is
// [DefaultVersion].
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
