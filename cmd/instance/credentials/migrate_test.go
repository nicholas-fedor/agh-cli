// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// TestRunMigratePreviewsWithoutWriting verifies that a dry run reports the change
// and performs no write.
func TestRunMigratePreviewsWithoutWriting(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.MigrationReport{
			Backend: testBackend,
			Service: testService,
			DryRun:  true,
			Results: []app.MigrationResult{
				{
					Instance: testInstanceName,
					Key:      testKeyringKey,
					DryRun:   true,
					Migrated: false,
					Err:      nil,
				},
			},
			Saved: false,
			Err:   nil,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		"",
		migrateCommandName,
		"--"+dryRunFlagName,
	)

	require.NoError(t, run.err)
	assert.True(t, store.dryRun)
	assert.Equal(
		t,
		"would migrate \"default\" to keyring key \"default\"\n"+
			"backend: keyring\n"+
			"service: agh-cli\n"+
			"nothing was written: 1 credential(s) would be migrated\n",
		run.out,
	)
}

// TestRunMigrateReportsAppliedMigration verifies the applied migration report.
func TestRunMigrateReportsAppliedMigration(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.MigrationReport{
			Backend: testBackend,
			Service: testService,
			DryRun:  false,
			Results: []app.MigrationResult{
				{
					Instance: testInstanceName,
					Key:      testKeyringKey,
					DryRun:   false,
					Migrated: true,
					Err:      nil,
				},
			},
			Saved: true,
			Err:   nil,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, "", migrateCommandName)

	require.NoError(t, run.err)
	assert.False(t, store.dryRun)
	assert.Equal(
		t,
		"migrated \"default\" to keyring key \"default\"\n"+
			"backend: keyring\n"+
			"service: agh-cli\n"+
			"configuration updated: 1 credential(s) migrated\n",
		run.out,
	)
}

// TestRunMigrateReportsNothingToDo verifies the converged report.
func TestRunMigrateReportsNothingToDo(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.MigrationReport{
			Backend: testBackend,
			Service: testService,
			Results: []app.MigrationResult{},
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, "", migrateCommandName)

	require.NoError(t, run.err)
	assert.Equal(
		t,
		"backend: keyring\nservice: agh-cli\nno plaintext credentials to migrate\n",
		run.out,
	)
}

// TestRunMigrateReportsPerInstanceOutcome verifies that every instance is named
// even when the run failed, so a partial migration stays visible.
func TestRunMigrateReportsPerInstanceOutcome(t *testing.T) {
	t.Parallel()

	saveErr := errors.New("configuration file is read-only")

	store := &fakeCoordinator{
		report: app.MigrationReport{
			Backend: testBackend,
			Service: testService,
			Results: []app.MigrationResult{
				{
					Instance: testInstanceName,
					Key:      testKeyringKey,
					Migrated: true,
					Err:      nil,
				},
				{
					Instance: "beta",
					Key:      "beta",
					Migrated: false,
					Err:      errors.New("credential store unavailable"),
				},
			},
			Saved: false,
			Err:   saveErr,
		},
		migrateErr: errors.New("some credentials were not migrated"),
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, "", migrateCommandName)

	require.Error(t, run.err)
	assert.Contains(
		t,
		run.out,
		"failed to migrate \"beta\" to keyring key \"beta\": "+
			"credential store unavailable",
	)
	assert.Contains(t, run.out, "configuration not updated: "+saveErr.Error())
}

// TestRunMigrateWarnsAboutUnsavedConfiguration verifies that a migration that
// reached the store but could not rewrite the file is reported as incomplete.
func TestRunMigrateWarnsAboutUnsavedConfiguration(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.MigrationReport{
			Backend: testBackend,
			Service: testService,
			Results: []app.MigrationResult{
				{
					Instance: testInstanceName,
					Key:      testKeyringKey,
					Migrated: true,
					Err:      nil,
				},
			},
			Saved: false,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, "", migrateCommandName)

	require.NoError(t, run.err)
	assert.Contains(
		t,
		run.out,
		"configuration not updated: the file still holds every plaintext password",
	)
}

// TestRunMigrateNeverReadsOrPrintsAPassword verifies the central migration
// invariant: the command reads no secret from its input and renders only
// instance identities and credential keys.
func TestRunMigrateNeverReadsOrPrintsAPassword(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		report: app.MigrationReport{
			Backend: testBackend,
			Service: testService,
			Results: []app.MigrationResult{
				{
					Instance: testInstanceName,
					Key:      testKeyringKey,
					Migrated: true,
					Err:      errors.New("write rejected the credential"),
				},
			},
			Saved: true,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, testSecret, migrateCommandName)

	require.NoError(t, run.err)
	assert.Empty(t, store.secret)
	assert.NotContains(t, run.out, testSecret)
	assert.NotContains(t, run.errOut, testSecret)
	assert.Contains(t, run.out, "failed to migrate \"default\" to keyring key \"default\"")
}

// TestRunMigrateRejectsPositionalArguments verifies the published argument
// arity.
func TestRunMigrateRejectsPositionalArguments(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, "", migrateCommandName, testInstanceName)

	require.Error(t, run.err)
	assert.Equal(t, 0, store.migrations)
}
