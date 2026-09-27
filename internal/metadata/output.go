// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// PrintDefault writes the application name and single-line version to writer.
//
// Parameters:
//   - writer: destination for the version string.
//
// Returns:
//   - error: non-nil when writing fails.
func PrintDefault(writer io.Writer) error {
	_, err := io.WriteString(writer, Name+" "+String()+"\n")
	if err != nil {
		return fmt.Errorf("write default output: %w", err)
	}

	return nil
}

// PrintVerbose writes detailed version and build metadata to writer.
//
// Parameters:
//   - writer: destination for the version details.
//
// Returns:
//   - error: non-nil when writing fails.
func PrintVerbose(writer io.Writer) error {
	info := GetInfo()

	lines := []string{
		"name:      " + info.Name,
		"version:   " + info.Version,
	}
	if info.CommitSHA != emptyString {
		lines = append(lines, "commitSha: "+info.CommitSHA)
	}

	if info.BuildTime != emptyString {
		lines = append(lines, "buildTime: "+info.BuildTime)
	}

	lines = append(lines,
		"goVersion: "+info.GoVersion,
		"os:        "+info.OS,
		"arch:      "+info.Arch,
	)

	content := strings.Join(lines, "\n") + "\n"

	_, err := io.WriteString(writer, content)
	if err != nil {
		return fmt.Errorf("write verbose output: %w", err)
	}

	return nil
}

// PrintJSON writes indented JSON version metadata to writer.
//
// Parameters:
//   - writer: destination for the encoded JSON.
//
// Returns:
//   - error: non-nil when encoding or writing fails.
func PrintJSON(writer io.Writer) error {
	info := GetInfo()

	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")

	err := enc.Encode(info)
	if err != nil {
		return fmt.Errorf("encode json: %w", err)
	}

	return nil
}
