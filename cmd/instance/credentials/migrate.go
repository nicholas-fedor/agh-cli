// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newMigrateCommand creates the credentials migrate command and binds its flags.
//
// Migration is never implicit, so the command must be invoked deliberately and a
// dry run is available before it is applied.
//
// Returns:
//   - *cobra.Command: The migrate command with its own flag values.
func newMigrateCommand() *cobra.Command {
	values := new(flags.MigrateFlags)

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
			return runMigrate(cmd, values)
		},
	}

	values.Bind(command.Flags())

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
//
// Returns:
//   - error: a wrapped error when no configuration is loaded, the credential
//     store is unusable, at least one instance was not migrated, or the
//     configuration file cannot be written.
func runMigrate(cmd *cobra.Command, values *flags.MigrateFlags) error {
	report, migrateErr := app.MigrateCredentials(cmd.Context(), credentials.MigrationRequest{
		DryRun: values.DryRun,
	})

	outputErr := output.WriteMigration(cmd.OutOrStderr(), report)

	migrateErr = errors.Join(migrateErr, outputErr)
	if migrateErr != nil {
		return fmt.Errorf("migrate credentials: %w", migrateErr)
	}

	return nil
}
