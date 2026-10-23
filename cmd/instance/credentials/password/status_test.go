// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// TestRunStatusReportsEveryInstance verifies the human-readable report for a
// configuration that mixes credential sources.
func TestRunStatusReportsEveryInstance(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		passwordReport: credentials.PasswordReport{
			Backend:   testBackend,
			Service:   testService,
			Available: true,
			Instances: []credentials.PasswordStatus{
				keyringStatus(testInstanceName, credentials.PresencePresent, nil),
				fileStatus("file-source", credentials.PresenceUnknown, nil),
				envStatus("env-source", credentials.PresenceUnknown, nil),
				plaintextStatus("legacy", credentials.PresencePresent),
			},
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", statusCommandName)

	require.NoError(t, run.err)
	assert.Empty(t, store.names)
	assert.Equal(
		t,
		"backend: keyring\n"+
			"service: agh-cli\n"+
			"available: true\n"+
			"instance \"default\": source keyring, key \"default\", present\n"+
			"instance \"file-source\": source file, path \"/run/secrets/adguard\", unknown\n"+
			"instance \"env-source\": source env, variable \"ADGUARD_PASSWORD\", unknown\n"+
			"instance \"legacy\": source plaintext, present\n",
		run.out,
	)
	assert.NotContains(t, run.out, testSecret)
}

// TestRunStatusReportsUnavailableKeyring verifies that a failed store read is
// reported as unknown with its reason instead of as an absence.
func TestRunStatusReportsUnavailableKeyring(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		passwordReport: credentials.PasswordReport{
			Backend:   testBackend,
			Service:   testService,
			Available: false,
			Instances: []credentials.PasswordStatus{
				keyringStatus(
					testInstanceName,
					credentials.PresenceUnknown,
					errors.New("credential store unavailable"),
				),
			},
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", statusCommandName)

	require.NoError(t, run.err)
	assert.Equal(
		t,
		"backend: keyring\n"+
			"service: agh-cli\n"+
			"available: false\n"+
			"instance \"default\": source keyring, key \"default\", "+
			"unknown: credential store unavailable\n",
		run.out,
	)
}

// TestRunStatusSelectsNamedInstance verifies that a single instance is inspected
// by name.
func TestRunStatusSelectsNamedInstance(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		passwordReport: credentials.PasswordReport{
			Backend:   testBackend,
			Service:   testService,
			Available: true,
			Instances: []credentials.PasswordStatus{},
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", statusCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Equal(t, []string{testInstanceName}, store.names)
}

// TestRunStatusRendersMachineReadableReport verifies the JSON report and that it
// carries configuration state only.
func TestRunStatusRendersMachineReadableReport(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		passwordReport: credentials.PasswordReport{
			Backend:   testBackend,
			Service:   testService,
			Available: true,
			Instances: []credentials.PasswordStatus{
				keyringStatus(testInstanceName, credentials.PresencePresent, nil),
				envStatus("env-source", credentials.PresenceUnknown, nil),
				keyringStatus(
					"broken",
					credentials.PresenceUnknown,
					errors.New("credential store unavailable"),
				),
			},
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", statusCommandName, "--"+jsonFlagName)

	require.NoError(t, run.err)
	assert.NotContains(t, run.out, testSecret)

	var report passwordReport

	require.NoError(t, json.Unmarshal([]byte(run.out), &report))

	assert.Equal(t, testBackend, report.Backend)
	assert.Equal(t, testService, report.Service)
	assert.True(t, report.Available)
	require.Len(t, report.Instances, 3)

	assert.Equal(t, "default", report.Instances[0].Instance)
	assert.Equal(t, "keyring", report.Instances[0].Source)
	assert.Equal(t, "default", report.Instances[0].Target)
	assert.Equal(t, "present", report.Instances[0].Presence)
	assert.Empty(t, report.Instances[0].Error)

	assert.Equal(t, testCredentialEnv, report.Instances[1].Target)
	assert.Equal(t, "unknown", report.Instances[1].Presence)
	assert.Empty(t, report.Instances[1].Error)

	assert.Equal(t, "credential store unavailable", report.Instances[2].Error)
}

// TestRunStatusOmitsEmptyTargetFromJSON verifies that a source owning no
// identity reports no target field.
func TestRunStatusOmitsEmptyTargetFromJSON(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		passwordReport: credentials.PasswordReport{
			Backend:   testBackend,
			Service:   testService,
			Available: true,
			Instances: []credentials.PasswordStatus{
				plaintextStatus("legacy", credentials.PresenceAbsent),
			},
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", statusCommandName, "--"+jsonFlagName)

	require.NoError(t, run.err)
	assert.NotContains(t, run.out, "target")
	assert.NotContains(t, run.out, "error")
}

// TestRunStatusForwardsUnknownInstance verifies that an unknown name reaches the
// operator.
func TestRunStatusForwardsUnknownInstance(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		statusErr: errors.New("instance \"nope\" not found"),
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", statusCommandName, "nope")

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "not found")
}

// TestRunStatusRejectsExtraArguments verifies the published argument arity.
func TestRunStatusRejectsExtraArguments(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runPassword(
		t,
		seams,
		"",
		statusCommandName,
		testInstanceName,
		"extra",
	)

	require.Error(t, run.err)
	assert.Empty(t, store.names)
}

// TestPresenceLabelCoversEveryValue verifies that every presence renders a
// defined label.
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

// TestWriteStatusTextReportsWriteFailure verifies that a failing report stream is
// reported.
func TestWriteStatusTextReportsWriteFailure(t *testing.T) {
	t.Parallel()

	err := writeStatusText(&failingWriter{}, credentials.PasswordReport{Backend: testBackend})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "write credential status")
}

// TestWriteStatusJSONReportsEncodeFailure verifies that a failing report stream
// is reported by the JSON writer too.
func TestWriteStatusJSONReportsEncodeFailure(t *testing.T) {
	t.Parallel()

	err := writeStatusJSON(&failingWriter{}, credentials.PasswordReport{Backend: testBackend})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "encode credential status")
}

// keyringStatus builds a keyring-backed credential state.
//
// Parameters:
//   - name: reported instance name.
//   - presence: reported presence.
//   - err: reported read failure, or nil.
//
// Returns:
//   - credentials.PasswordStatus: the keyring-backed state.
func keyringStatus(name string, presence credentials.Presence, err error) credentials.PasswordStatus {
	return credentials.PasswordStatus{
		Instance:   name,
		Source:     instance.KeyringSource,
		Target:     name,
		TargetKind: "key",
		Presence:   presence,
		Err:        err,
	}
}

// fileStatus builds a mounted-secret credential state.
//
// Parameters:
//   - name: reported instance name.
//   - presence: reported presence.
//   - err: reported read failure, or nil.
//
// Returns:
//   - credentials.PasswordStatus: the mounted-secret state.
func fileStatus(name string, presence credentials.Presence, err error) credentials.PasswordStatus {
	return credentials.PasswordStatus{
		Instance:   name,
		Source:     instance.FileSource,
		Target:     testCredentialFile,
		TargetKind: "path",
		Presence:   presence,
		Err:        err,
	}
}

// envStatus builds an environment-backed credential state.
//
// Parameters:
//   - name: reported instance name.
//   - presence: reported presence.
//   - err: reported read failure, or nil.
//
// Returns:
//   - credentials.PasswordStatus: the environment-backed state.
func envStatus(name string, presence credentials.Presence, err error) credentials.PasswordStatus {
	return credentials.PasswordStatus{
		Instance:   name,
		Source:     instance.EnvSource,
		Target:     testCredentialEnv,
		TargetKind: "variable",
		Presence:   presence,
		Err:        err,
	}
}

// plaintextStatus builds a legacy plaintext credential state.
//
// Parameters:
//   - name: reported instance name.
//   - presence: reported presence.
//   - err: reported read failure, or nil.
//
// Returns:
//   - credentials.PasswordStatus: the legacy plaintext state.
func plaintextStatus(
	name string,
	presence credentials.Presence,
) credentials.PasswordStatus {
	return credentials.PasswordStatus{
		Instance:   name,
		Source:     instance.PlaintextSource,
		Target:     "",
		TargetKind: "",
		Presence:   presence,
		Err:        nil,
	}
}
