// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package main provides the documentation generator for the agh-cli command
// tree.
//
// The generator introspects the Cobra command tree returned by
// [github.com/nicholas-fedor/agh-cli/cmd.NewRootCommand] and writes
// Hugo-compatible Markdown pages with front matter. The command tree is never
// executed, so generation has no side effects on configured instances.
//
// Usage:
//
//	go run ./tools/docgen -out ./www/content/cli-reference
package main

import (
	"flag"
	"log"

	"github.com/nicholas-fedor/agh-cli/cmd"
)

const (
	// Name of the output directory flag.
	outputFlagName = "out"

	// Default documentation output directory.
	defaultOutputDir = "./www/content/cli-reference"
)

// main generates the CLI reference documentation for the command tree.
func main() {
	outputDir := flag.String(outputFlagName, defaultOutputDir, "Output directory")

	flag.Parse()

	generator, err := NewDocGenerator()
	if err != nil {
		log.Fatalf("create doc generator: %v", err)
	}

	err = generator.Generate(cmd.NewRootCommand(), *outputDir)
	if err != nil {
		log.Fatalf("generate documentation: %v", err)
	}
}
