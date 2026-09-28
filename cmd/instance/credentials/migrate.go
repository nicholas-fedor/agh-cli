// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// migrateValues stores the flag values bound to one migrate command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type migrateValues struct {
	// dryRun holds the --dry-run flag value.
	dryRun bool
}

// newMigrateCommand creates the credentials migrate command and binds its flags.
//
// Migration is never implicit, so the command must be invoked deliberately and a
// dry run is available before it is applied.
//
// Parameters:
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - *cobra.Command: The migrate command with its own flag values.
func newMigrateCommand(seams *streams) *cobra.Command {
	values := &migrateValues{}

	command := &cobra.Command{
		Use:   "migrate",
		Short: "Move legacy plaintext passwords into the credential store",
		Long: `Move the legacy plaintext password of every configured instance that
declares no credential source into the operating system credential store.
Use --dry-run first to preview the change. A password reaches the
credential store before it is removed from the configuration, and no
password is ever printed.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMigrate(cmd, values, seams)
		},
	}

	command.Flags().BoolVar(
		&values.dryRun,
		dryRunFlagName,
		false,
		"report the change without writing to the store or the configuration",
	)

	return command
}

// runMigrate moves legacy plaintext passwords into the credential store.
//
// The report is rendered before the error is returned, so a partial migration
// names every instance it did not convert.
//
// Parameters:
//   - cmd: Cobra command context.
//   - values: Bound flag values carrying the dry-run selection.
//   - seams: input seams and credential coordinator factory.
//
// Returns:
//   - error: a wrapped error when the coordinator cannot be built, the credential
//     store is unusable, at least one instance was not migrated, or the
//     configuration file cannot be written.
func runMigrate(cmd *cobra.Command, values *migrateValues, seams *streams) error {
	store, err := seams.coordinator()
	if err != nil {
		return fmt.Errorf("build credential coordinator: %w", err)
	}

	report, migrateErr := store.Migrate(cmd.Context(), app.MigrationRequest{
		DryRun: values.dryRun,
	})

	reportMigration(cmd, report)

	if migrateErr != nil {
		return fmt.Errorf("migrate credentials: %w", migrateErr)
	}

	return nil
}

// reportMigration renders the outcome of one migration run.
//
// Every line names an instance and a credential key. A password, and any value
// derived from one, never reaches an output stream.
//
// Parameters:
//   - cmd: Cobra command context.
//   - report: outcome of the migration run.
func reportMigration(cmd *cobra.Command, report app.MigrationReport) {
	for _, result := range report.Results {
		cmd.Println(migrationLine(result))
	}

	cmd.Printf(
		"backend: %s\nservice: %s\n%s\n",
		report.Backend,
		report.Service,
		migrationSummary(report),
	)
}

// migrationLine renders the outcome of one migrated instance.
//
// Parameters:
//   - result: outcome of one instance migration.
//
// Returns:
//   - string: the rendered line.
func migrationLine(result app.MigrationResult) string {
	subject := strconv.Quote(result.Instance) + " to keyring key " + strconv.Quote(result.Key)

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
func migrationSummary(report app.MigrationReport) string {
	if report.DryRun {
		return fmt.Sprintf(
			"nothing was written: %d credential(s) would be migrated",
			len(report.Results),
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

	return fmt.Sprintf("configuration updated: %d credential(s) migrated", len(report.Results))
}
