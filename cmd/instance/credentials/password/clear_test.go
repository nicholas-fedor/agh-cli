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
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/internal/prompt"
)

// TestRunClearRemovesNamedCredential verifies that the stored credential of one
// instance is deleted and reported.
func TestRunClearRemovesNamedCredential(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, keyringDocument)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, testInstanceName).Return(testSecret, nil).Once()
	store.EXPECT().Delete(mock.Anything, credentials.DefaultService, testInstanceName).Return(nil).Once()

	run := runPassword(ctx, t, nil, clearCommandName, testInstanceName, "--"+yesFlagName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, `Removed credential for instance "default" with key "default"`)
	assert.NotContains(t, run.out+run.errOut, testSecret)
}

// TestRunClearRemovesWholeService verifies that --all deletes every credential
// of the configured service.
func TestRunClearRemovesWholeService(t *testing.T) {
	t.Parallel()

	ctx, store := storeContext(t, keyringDocument)
	store.EXPECT().DeleteAll(mock.Anything, credentials.DefaultService).Return(nil).Once()

	run := runPassword(ctx, t, nil, clearCommandName, "--"+allFlagName, "--"+yesFlagName)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, `Removed every credential in service "agh-cli".`)
}

// TestRunClearRejectsAmbiguousSelection verifies that a clear must name exactly
// one of an instance and the whole service, before the store is reached.
func TestRunClearRejectsAmbiguousSelection(t *testing.T) {
	t.Parallel()

	for name, args := range map[string][]string{
		"neither":          {clearCommandName, "--" + yesFlagName},
		"instance and all": {clearCommandName, testInstanceName, "--" + allFlagName, "--" + yesFlagName},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, _ := storeContext(t, keyringDocument)

			run := runPassword(ctx, t, nil, args...)

			require.ErrorIs(t, run.err, flags.ErrInvalidSelection)
		})
	}
}

// TestRunClearDeclinedConfirmationDeletesNothing verifies that a declined
// confirmation never reaches the store and says so.
func TestRunClearDeclinedConfirmationDeletesNothing(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, keyringDocument)

	run := runPassword(ctx, t, terminalInput{Reader: strings.NewReader("n\n"), hidden: ""},
		clearCommandName, testInstanceName)

	require.NoError(t, run.err)
	assert.Contains(t, run.errOut, "Canceled; no credential was removed.")
}

// TestRunClearRequiresConfirmationWithoutTerminal verifies that a redirected
// workflow cannot delete a credential without --yes.
func TestRunClearRequiresConfirmationWithoutTerminal(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, keyringDocument)

	run := runPassword(ctx, t, nil, clearCommandName, "--"+allFlagName)

	require.ErrorIs(t, run.err, prompt.ErrConfirmationUnavailable)
}

// TestRunClearRefusesExternalSource verifies that a password owned by another
// system is never deleted, and that the store is never reached.
func TestRunClearRefusesExternalSource(t *testing.T) {
	t.Parallel()

	ctx, _ := storeContext(t, envDocument)

	run := runPassword(ctx, t, nil, clearCommandName, testInstanceName, "--"+yesFlagName)

	require.ErrorIs(t, run.err, credentials.ErrExternalCredentialSource)
}

// TestRunClearForwardsStoreFailure verifies that a store failure names the
// instance.
func TestRunClearForwardsStoreFailure(t *testing.T) {
	t.Parallel()

	storeErr := errors.New("keyring is locked")

	ctx, store := storeContext(t, keyringDocument)
	store.EXPECT().Get(mock.Anything, credentials.DefaultService, testInstanceName).Return(testSecret, nil).Once()
	store.EXPECT().Delete(mock.Anything, credentials.DefaultService, testInstanceName).Return(storeErr).Once()

	run := runPassword(ctx, t, nil, clearCommandName, testInstanceName, "--"+yesFlagName)

	require.ErrorIs(t, run.err, storeErr)
	assert.Contains(t, run.err.Error(), `clear credential of "default"`)
}
