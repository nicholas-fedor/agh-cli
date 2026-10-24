// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TestWriteInstanceNamesWritesOneNamePerLine verifies the instance list.
func TestWriteInstanceNamesWritesOneNamePerLine(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WriteInstanceNames(&rendered, []instance.Config{namedConfig("alpha"), namedConfig("zulu")}))
	require.NoError(t, WriteInstanceAdded(&rendered, "beta"))
	assert.Equal(t, "alpha\nzulu\nInstance \"beta\" added\n", rendered.String())
}

// TestWriteInstanceRemovalReportsCredentialOutcome verifies the removal line and
// the credential outcome for every kind of removal.
func TestWriteInstanceRemovalReportsCredentialOutcome(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		removal credentials.InstancePasswordRemoval
		want    string
	}{
		"no stored credential": {
			removal: credentials.InstancePasswordRemoval{Service: "agh-cli"},
			want:    "Instance \"alpha\" removed\n",
		},
		"removed": {
			removal: credentials.InstancePasswordRemoval{Service: "agh-cli", Key: "alpha", Removed: true},
			want: "Instance \"alpha\" removed\n" +
				"Removed credential for instance \"alpha\" with key \"alpha\" from service \"agh-cli\".\n",
		},
		"already absent": {
			removal: credentials.InstancePasswordRemoval{Service: "agh-cli", Key: "alpha"},
			want: "Instance \"alpha\" removed\n" +
				"No stored credential for instance \"alpha\" with key \"alpha\" in service \"agh-cli\".\n",
		},
		"shared": {
			removal: credentials.InstancePasswordRemoval{Service: "agh-cli", Key: "shared", Shared: true},
			want: "Instance \"alpha\" removed\n" +
				"Kept credential with key \"shared\" in service \"agh-cli\": another configured " +
				"instance still reads its password through it.\n",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var rendered bytes.Buffer

			result := app.InstanceRemoveResult{InstancePasswordRemoval: test.removal, Instance: "alpha"}

			require.NoError(t, WriteInstanceRemoval(&rendered, result))
			assert.Equal(t, test.want, rendered.String())
		})
	}
}

// TestWriteFailedInstanceRemovalReportsDeletedCredential verifies that a failed
// removal reports a deleted credential, and reports nothing otherwise.
func TestWriteFailedInstanceRemovalReportsDeletedCredential(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WriteFailedInstanceRemoval(&rendered, app.InstanceRemoveResult{Instance: "alpha"}))
	assert.Empty(t, rendered.String())

	removed := app.InstanceRemoveResult{
		Service: "agh-cli", Key: "alpha", Removed: true,
		Instance: "alpha",
	}

	require.NoError(t, WriteFailedInstanceRemoval(&rendered, removed))
	assert.Equal(t,
		"Removed credential for instance \"alpha\" with key \"alpha\" from service \"agh-cli\". "+
			"Instance \"alpha\" remains configured; run the command again to remove it.\n",
		rendered.String(),
	)
}

// TestWriteInstanceWritersReportWriteFailures verifies that every instance writer
// reports a destination that rejects output.
func TestWriteInstanceWritersReportWriteFailures(t *testing.T) {
	t.Parallel()

	failing := errorWriter{err: errWriteFailed}
	removed := app.InstanceRemoveResult{
		Service: "agh-cli", Key: "alpha", Removed: true,
		Instance: "alpha",
	}

	require.ErrorIs(t, WriteInstanceNames(failing, []instance.Config{namedConfig("alpha")}), errWriteFailed)
	require.ErrorIs(t, WriteInstanceAdded(failing, "alpha"), errWriteFailed)
	require.ErrorIs(t, WriteInstanceRemoval(failing, removed), errWriteFailed)
	require.ErrorIs(t, WriteFailedInstanceRemoval(failing, removed), errWriteFailed)
}

// namedConfig returns an instance configuration that carries only a name.
//
// Parameters:
//   - name: instance name.
//
// Returns:
//   - [instance.Config]: the configuration with every other field empty.
func namedConfig(name string) instance.Config {
	return instance.Config{Name: name, Host: "", Scheme: "", Username: "", Password: "", Credential: nil}
}
