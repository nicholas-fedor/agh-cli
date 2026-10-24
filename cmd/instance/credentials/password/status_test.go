// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// statusDocument is the shape the JSON status report is decoded into.
type statusDocument struct {
	// Backend is the credential store backend name.
	Backend string `json:"backend"`
	// Instances contains one entry per inspected instance.
	Instances []statusDocumentEntry `json:"instances"`
	// Available reports whether every credential store read succeeded.
	Available bool `json:"available"`
}

// statusDocumentEntry is the shape one JSON status entry is decoded into.
type statusDocumentEntry struct {
	// Instance is the inspected instance name.
	Instance string `json:"instance"`
	// Source is the configured credential source.
	Source string `json:"source"`
	// Presence reports how the source supplies a password.
	Presence string `json:"presence"`
}

// mixedDocument configures one instance per credential source.
const mixedDocument = "instances:\n" +
	"  default:\n" +
	"    host: a.example\n" +
	"    credential:\n" +
	"      source: keyring\n" +
	"      key: default\n" +
	"  mounted:\n" +
	"    host: b.example\n" +
	"    credential:\n" +
	"      source: file\n" +
	"      path: /run/secrets/adguard\n" +
	"  legacy:\n" +
	"    host: c.example\n" +
	"    password: " + testSecret + "\n"

// TestRunStatusReportsEveryInstance verifies the text report over every
// configured source, and that a stored secret is never printed.
func TestRunStatusReportsEveryInstance(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, mixedDocument)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, testInstanceName).Return(testSecret, nil).Once()

	run := runPassword(ctx, t, nil, statusCommandName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, `instance "default": source keyring, key "default", present`)
	assert.Contains(t, run.out, `instance "mounted": source file, path "/run/secrets/adguard"`)
	assert.Contains(t, run.out, `instance "legacy": source plaintext, present`)
	assert.NotContains(t, run.out+run.errOut, testSecret)
}

// TestRunStatusRendersMachineReadableReport verifies that --json selects the
// machine-readable report.
func TestRunStatusRendersMachineReadableReport(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, keyringDocument)
	expectStoredAbsent(store, testInstanceName)

	run := runPassword(ctx, t, nil, statusCommandName, "--"+jsonFlagName)

	require.NoError(t, run.err)

	var report statusDocument

	require.NoError(t, json.Unmarshal([]byte(run.out), &report))
	assert.Equal(t, statusDocument{
		Backend:   credentials.KeyringBackend,
		Instances: []statusDocumentEntry{{Instance: testInstanceName, Source: "keyring", Presence: "absent"}},
		Available: true,
	}, report)
}

// TestRunStatusSelectsNamedInstance verifies that a named instance is the only
// one inspected.
func TestRunStatusSelectsNamedInstance(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, mixedDocument)

	run := runPassword(ctx, t, nil, statusCommandName, "legacy")

	require.NoError(t, run.err)
	assert.Contains(t, run.out, `instance "legacy"`)
	assert.NotContains(t, run.out, `instance "default"`)
}

// TestRunStatusForwardsUnknownInstance verifies that an unknown name reaches the
// operator.
func TestRunStatusForwardsUnknownInstance(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, keyringDocument)

	run := runPassword(ctx, t, nil, statusCommandName, "nope")

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "report credential status")
}

// TestRunStatusRejectsExtraArguments verifies the published argument arity.
func TestRunStatusRejectsExtraArguments(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, keyringDocument)

	run := runPassword(ctx, t, nil, statusCommandName, testInstanceName, "extra")

	require.Error(t, run.err)
}
