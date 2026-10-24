// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// TestWriteMigrationReportsEveryOutcome verifies the per-instance lines and the
// closing summary of a dry run, an applied run, an empty run, and a run whose
// configuration was not updated.
func TestWriteMigrationReportsEveryOutcome(t *testing.T) {
	t.Parallel()

	refused := errors.New("key in use")

	tests := map[string]struct {
		report credentials.MigrationReport
		want   string
	}{
		"dry run": {
			report: credentials.MigrationReport{
				Backend: "keyring",
				Service: "agh-cli",
				DryRun:  true,
				Results: []credentials.MigrationResult{
					{Instance: "alpha", Key: "alpha", DryRun: true},
					{Instance: "beta", Key: "beta", DryRun: true, Err: refused},
				},
			},
			want: "would migrate \"alpha\" to keyring key \"alpha\"\n" +
				"would not migrate \"beta\" to keyring key \"beta\": key in use\n" +
				"backend: keyring\nservice: agh-cli\nnothing was written: 1 credential(s) would be migrated\n",
		},
		"applied": {
			report: credentials.MigrationReport{
				Backend: "keyring",
				Service: "agh-cli",
				Saved:   true,
				Results: []credentials.MigrationResult{
					{Instance: "alpha", Key: "alpha", Migrated: true},
					{Instance: "beta", Key: "beta", Err: refused},
				},
			},
			want: "migrated \"alpha\" to keyring key \"alpha\"\n" +
				"failed to migrate \"beta\" to keyring key \"beta\": key in use\n" +
				"backend: keyring\nservice: agh-cli\nconfiguration updated: 1 credential(s) migrated\n",
		},
		"nothing to migrate": {
			report: credentials.MigrationReport{Backend: "keyring", Service: "agh-cli"},
			want:   "backend: keyring\nservice: agh-cli\nno plaintext credentials to migrate\n",
		},
		"not saved": {
			report: credentials.MigrationReport{
				Backend: "keyring",
				Service: "agh-cli",
				Results: []credentials.MigrationResult{{Instance: "alpha", Key: "alpha", Migrated: true}},
			},
			want: "migrated \"alpha\" to keyring key \"alpha\"\n" +
				"backend: keyring\nservice: agh-cli\n" +
				"configuration not updated: the file still holds every plaintext password\n",
		},
		"write failed": {
			report: credentials.MigrationReport{
				Backend: "keyring",
				Service: "agh-cli",
				Err:     errors.New("disk full"),
				Results: []credentials.MigrationResult{{Instance: "alpha", Key: "alpha", Migrated: true}},
			},
			want: "migrated \"alpha\" to keyring key \"alpha\"\n" +
				"backend: keyring\nservice: agh-cli\nconfiguration not updated: disk full\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var rendered bytes.Buffer

			require.NoError(t, WriteMigration(&rendered, test.report))
			assert.Equal(t, test.want, rendered.String())
		})
	}
}

// TestWriteMigrationReportsWriteFailures verifies that a failed outcome line and
// a failed summary are both reported.
func TestWriteMigrationReportsWriteFailures(t *testing.T) {
	t.Parallel()

	failing := errorWriter{err: errWriteFailed}

	withResult := credentials.MigrationReport{
		Results: []credentials.MigrationResult{{Instance: "alpha", Key: "alpha"}},
	}

	require.ErrorIs(t, WriteMigration(failing, withResult), errWriteFailed)
	require.ErrorIs(t, WriteMigration(failing, credentials.MigrationReport{}), errWriteFailed)
}
