// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"fmt"
	"io"
	"strconv"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// WriteMigration writes the outcome of one migration run.
//
// Every line names an instance and a credential key. A password, and any value
// derived from one, never reaches an output stream.
//
// Parameters:
//   - writer: destination for the outcome.
//   - report: outcome of the migration run.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WriteMigration(writer io.Writer, report credentials.MigrationReport) error {
	for _, result := range report.Results {
		_, err := fmt.Fprintln(writer, migrationLine(result))
		if err != nil {
			return fmt.Errorf("write migration outcome: %w", err)
		}
	}

	_, err := fmt.Fprintf(
		writer,
		"backend: %s\nservice: %s\n%s\n",
		report.Backend,
		report.Service,
		migrationSummary(report),
	)
	if err != nil {
		return fmt.Errorf("write migration summary: %w", err)
	}

	return nil
}

// migrationLine renders the outcome of one migrated instance.
//
// Parameters:
//   - result: outcome of one instance migration.
//
// Returns:
//   - string: the rendered line.
func migrationLine(result credentials.MigrationResult) string {
	subject := strconv.Quote(result.Instance) + " to keyring key " + strconv.Quote(result.Key)

	if result.DryRun && result.Err != nil {
		return "would not migrate " + subject + ": " + result.Err.Error()
	}

	if result.DryRun {
		return "would migrate " + subject
	}

	if result.Err != nil {
		return "failed to migrate " + subject + ": " + result.Err.Error()
	}

	return "migrated " + subject
}

// migrationSummary renders the closing line of a migration run.
//
// The summary names the configuration outcome, because a migration that reached
// the credential store but could not rewrite the file still leaves a plaintext
// password on disk.
//
// Parameters:
//   - report: outcome of the migration run.
//
// Returns:
//   - string: the rendered summary line.
func migrationSummary(report credentials.MigrationReport) string {
	if report.DryRun {
		return fmt.Sprintf(
			"nothing was written: %d credential(s) would be migrated",
			migratable(report.Results),
		)
	}

	if len(report.Results) == 0 {
		return "no plaintext credentials to migrate"
	}

	if report.Err != nil {
		return "configuration not updated: " + report.Err.Error()
	}

	if !report.Saved {
		return "configuration not updated: the file still holds every plaintext password"
	}

	return fmt.Sprintf("configuration updated: %d credential(s) migrated", migratable(report.Results))
}

// migratable counts the instances a migration run moved or would move.
//
// Parameters:
//   - results: outcomes of the migration run.
//
// Returns:
//   - int: the number of outcomes without an error.
func migratable(results []credentials.MigrationResult) int {
	count := 0

	for _, result := range results {
		if result.Err == nil {
			count++
		}
	}

	return count
}
