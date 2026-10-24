// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
	"github.com/nicholas-fedor/agh-cli/internal/prompt"
)

// TestRunSetReadsRedirectedSecret verifies the non-interactive write path, and
// that no output stream ever carries the secret.
func TestRunSetReadsRedirectedSecret(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, legacyDocument)
	expectStoredAbsent(store, testInstanceName)
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, testInstanceName, testSecret).Return(nil).Once()

	run := runPassword(ctx, t, strings.NewReader(testSecret+"\n"), setCommandName, testInstanceName, "--"+yesFlagName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, `Stored credential for instance "default"`)
	assert.NotContains(t, run.out+run.errOut, testSecret)
}

// TestRunSetUsesHiddenTerminalPrompt verifies that a terminal input is read
// through the hidden prompt and confirmed before it is stored.
func TestRunSetUsesHiddenTerminalPrompt(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, legacyDocument)
	expectStoredAbsent(store, testInstanceName)
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, testInstanceName, testSecret).Return(nil).Once()

	input := terminalInput{Reader: strings.NewReader("y\n"), hidden: testSecret}
	run := runPassword(ctx, t, input, setCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Contains(t, run.errOut, "Password: ")
	assert.Contains(t, run.errOut, `Store this credential for instance "default"? [y/N]: `)
	assert.NotContains(t, run.out+run.errOut, testSecret)
}

// TestRunSetRequiresConfirmationWithoutTerminal verifies that a redirected
// secret is never stored without --yes. The store has no expectations, so any
// call fails the test.
func TestRunSetRequiresConfirmationWithoutTerminal(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, legacyDocument)

	run := runPassword(ctx, t, strings.NewReader(testSecret+"\n"), setCommandName, testInstanceName)

	require.ErrorIs(t, run.err, prompt.ErrConfirmationUnavailable)
	assert.NotContains(t, run.out+run.errOut+run.err.Error(), testSecret)
}

// TestRunSetDeclinedConfirmationStoresNothing verifies that a declined
// confirmation never reaches the store and says so.
func TestRunSetDeclinedConfirmationStoresNothing(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, legacyDocument)

	input := terminalInput{Reader: strings.NewReader("n\n"), hidden: testSecret}
	run := runPassword(ctx, t, input, setCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Contains(t, run.errOut, "Canceled; no credential was stored.")
}

// TestRunSetRejectsEmptySecret verifies that empty input never replaces a
// working password.
func TestRunSetRejectsEmptySecret(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, legacyDocument)

	run := runPassword(ctx, t, strings.NewReader("\n"), setCommandName, testInstanceName, "--"+yesFlagName)

	require.ErrorIs(t, run.err, prompt.ErrEmptySecret)
}

// TestRunSetForwardsCustomKey verifies that --key selects the credential key.
func TestRunSetForwardsCustomKey(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, legacyDocument)
	expectStoredAbsent(store, "adguard-production-admin")
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, "adguard-production-admin", testSecret).
		Return(nil).Once()

	run := runPassword(ctx, t, strings.NewReader(testSecret), setCommandName, testInstanceName,
		"--"+keyFlagName, "adguard-production-admin", "--"+yesFlagName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, `with key "adguard-production-admin"`)
}

// TestRunSetForwardsStoreFailure verifies that a store failure is reported with
// the instance name and without the secret.
func TestRunSetForwardsStoreFailure(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("keyring is locked")

	ctx, store := storeContext(t, legacyDocument)
	expectStoredAbsent(store, testInstanceName)
	store.EXPECT().Set(mock.Anything, credentials.DefaultService, testInstanceName, testSecret).Return(storeErr).Once()

	run := runPassword(ctx, t, strings.NewReader(testSecret), setCommandName, testInstanceName, "--"+yesFlagName)

	require.ErrorIs(t, run.err, storeErr)
	assert.Contains(t, run.err.Error(), `set credential for "default"`)
	assert.NotContains(t, run.err.Error(), testSecret)
}

// TestRunSetRequiresInstanceName verifies the published argument arity.
func TestRunSetRequiresInstanceName(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, legacyDocument)

	run := runPassword(ctx, t, strings.NewReader(testSecret), setCommandName)

	require.Error(t, run.err)
}
