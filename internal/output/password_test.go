// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// passwordTestReport is a report covering a stored key, an environment variable,
// and a store read that failed.
var passwordTestReport = credentials.PasswordReport{
	Backend:   "keyring",
	Service:   "agh-cli",
	Available: false,
	Instances: []credentials.PasswordStatus{
		{
			Instance: "alpha", Source: "keyring", Target: "alpha", TargetKind: "key",
			Presence: credentials.PresencePresent,
		},
		{
			Instance: "beta", Source: "env", Target: "BETA_PASSWORD", TargetKind: "variable",
			Presence: credentials.PresenceUnknown,
		},
		{
			Instance: "gamma", Source: "keyring", Target: "gamma", TargetKind: "key",
			Presence: credentials.PresenceUnknown, Err: errors.New("store locked"),
		},
		{Instance: "delta", Source: "plaintext", Target: "", TargetKind: "", Presence: credentials.PresenceAbsent},
	},
}

// TestWritePasswordStatusTextWritesEveryInstance verifies the text report.
func TestWritePasswordStatusTextWritesEveryInstance(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WritePasswordStatusText(&rendered, passwordTestReport))
	assert.Equal(t,
		"backend: keyring\n"+
			"service: agh-cli\n"+
			"available: false\n"+
			"instance \"alpha\": source keyring, key \"alpha\", present\n"+
			"instance \"beta\": source env, variable \"BETA_PASSWORD\", unknown\n"+
			"instance \"gamma\": source keyring, key \"gamma\", unknown: store locked\n"+
			"instance \"delta\": source plaintext, absent\n",
		rendered.String(),
	)
}

// TestWritePasswordStatusJSONWritesEveryInstance verifies the JSON report and
// that empty optional fields are left out.
func TestWritePasswordStatusJSONWritesEveryInstance(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WritePasswordStatusJSON(&rendered, passwordTestReport))

	var report passwordReport

	require.NoError(t, json.Unmarshal(rendered.Bytes(), &report))
	assert.Equal(t, passwordReport{
		Backend:   "keyring",
		Service:   "agh-cli",
		Available: false,
		Instances: []passwordEntry{
			{Instance: "alpha", Source: "keyring", Target: "alpha", Presence: "present", Error: ""},
			{Instance: "beta", Source: "env", Target: "BETA_PASSWORD", Presence: "unknown", Error: ""},
			{Instance: "gamma", Source: "keyring", Target: "gamma", Presence: "unknown", Error: "store locked"},
			{Instance: "delta", Source: "plaintext", Target: "", Presence: "absent", Error: ""},
		},
	}, report)
	assert.NotContains(t, rendered.String(), `"target": ""`)
}

// TestPresenceLabelCoversEveryValue verifies that every presence renders a
// defined label, and that an unexpected value is reported as unknown.
func TestPresenceLabelCoversEveryValue(t *testing.T) {
	t.Parallel()

	tests := map[credentials.Presence]string{
		credentials.PresencePresent: "present",
		credentials.PresenceAbsent:  "absent",
		credentials.PresenceUnknown: "unknown",
		credentials.Presence(9):     "unknown",
	}

	for presence, want := range tests {
		assert.Equal(t, want, presenceLabel(presence))
	}
}

// TestWritePasswordSetReportsOutcomeAndWarning verifies the stored and replaced
// outcomes, and the warning on the error stream when the file still holds the
// plaintext password.
func TestWritePasswordSetReportsOutcomeAndWarning(t *testing.T) {
	t.Parallel()

	var out, errOut bytes.Buffer

	result := credentials.PasswordSetResult{
		Instance: "alpha", Backend: "keyring", Service: "agh-cli", Key: "alpha", Replaced: true, Saved: false,
	}

	require.NoError(t, WritePasswordSet(&out, &errOut, result))
	assert.Equal(t,
		"Replaced credential for instance \"alpha\" in keyring service \"agh-cli\" with key \"alpha\".\n",
		out.String(),
	)
	assert.Contains(t, errOut.String(),
		"configuration file still holds the plaintext password for instance \"alpha\"")

	out.Reset()
	errOut.Reset()

	result.Replaced, result.Saved = false, true

	require.NoError(t, WritePasswordSet(&out, &errOut, result))
	assert.Contains(t, out.String(), "Stored credential")
	assert.Empty(t, errOut.String())
}

// TestWritePasswordClearReportsEveryOutcome verifies the kept, absent, and
// removed outcomes, and the warning for an unsaved reference.
func TestWritePasswordClearReportsEveryOutcome(t *testing.T) {
	t.Parallel()

	base := credentials.PasswordClearResult{Instance: "alpha", Service: "agh-cli", Key: "shared", Saved: true}

	tests := map[string]struct {
		mutate  func(*credentials.PasswordClearResult)
		want    string
		warning string
	}{
		"shared": {
			mutate: func(r *credentials.PasswordClearResult) { r.Shared = true },
			want: "Kept credential with key \"shared\" in service \"agh-cli\": " +
				"another configured instance still reads its password through it.\n",
		},
		"absent": {
			mutate: func(*credentials.PasswordClearResult) {},
			want:   "No stored credential for instance \"alpha\" with key \"shared\" in service \"agh-cli\".\n",
		},
		"removed and unsaved": {
			mutate:  func(r *credentials.PasswordClearResult) { r.Removed, r.Saved = true, false },
			want:    "Removed credential for instance \"alpha\" with key \"shared\" from service \"agh-cli\".\n",
			warning: "instance \"alpha\" still references it in the configuration file",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			result := base
			test.mutate(&result)

			var out, errOut bytes.Buffer

			require.NoError(t, WritePasswordClear(&out, &errOut, result))
			assert.Equal(t, test.want, out.String())

			if test.warning == "" {
				assert.Empty(t, errOut.String())
			} else {
				assert.Contains(t, errOut.String(), test.warning)
			}
		})
	}
}

// TestWritePasswordClearAllWritesOneLine verifies the service-wide clear notice.
func TestWritePasswordClearAllWritesOneLine(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WritePasswordClearAll(&rendered, credentials.PasswordClearResult{Service: "agh-cli"}))
	assert.Equal(t, "Removed every credential in service \"agh-cli\".\n", rendered.String())
}

// TestWritePasswordWritersReportWriteFailures verifies that every password writer
// reports a destination that rejects output.
func TestWritePasswordWritersReportWriteFailures(t *testing.T) {
	t.Parallel()

	failing := errorWriter{err: errWriteFailed}

	var ok bytes.Buffer

	require.ErrorIs(t, WritePasswordStatusText(failing, passwordTestReport), errWriteFailed)
	require.ErrorIs(t, WritePasswordStatusJSON(failing, passwordTestReport), errWriteFailed)
	require.ErrorIs(t, WritePasswordSet(failing, &ok, credentials.PasswordSetResult{Saved: true}), errWriteFailed)
	require.ErrorIs(t, WritePasswordSet(&ok, failing, credentials.PasswordSetResult{Saved: false}), errWriteFailed)
	require.ErrorIs(t, WritePasswordClear(failing, &ok, credentials.PasswordClearResult{}), errWriteFailed)
	require.ErrorIs(t,
		WritePasswordClear(&ok, failing, credentials.PasswordClearResult{Removed: true}),
		errWriteFailed,
	)
	require.ErrorIs(t, WritePasswordClearAll(failing, credentials.PasswordClearResult{}), errWriteFailed)
}
