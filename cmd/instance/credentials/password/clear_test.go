// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package password

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// TestRunClearRemovesNamedCredential verifies the single-instance clear and the
// confirmation prompt that guards it.
func TestRunClearRemovesNamedCredential(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		clearResult: app.PasswordClearResult{
			Instance: testInstanceName,
			Service:  testService,
			Key:      testKeyringKey,
			Removed:  true,
			Saved:    true,
		},
	}

	seams := testStreams(store, true, testSecret)

	run := runPassword(
		t,
		seams,
		"y\n",
		clearCommandName,
		testInstanceName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, 1, store.clears)
	assert.Equal(t, 0, store.clearAlls)
	assert.Equal(t, testInstanceName, store.name)
	assert.Contains(
		t,
		run.out,
		"Removed credential for instance \"default\" with key \"default\" "+
			"from service \"agh-cli\".",
	)
	assert.Contains(
		t,
		run.errOut,
		"Remove the stored credential of instance \"default\"?",
	)
}

// TestRunClearReportsAbsentCredential verifies that clearing an absent
// credential converges instead of failing.
func TestRunClearReportsAbsentCredential(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		clearResult: app.PasswordClearResult{
			Instance: testInstanceName,
			Service:  testService,
			Key:      testKeyringKey,
			Removed:  false,
			Saved:    true,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(
		t,
		seams,
		"",
		clearCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, "No stored credential for instance \"default\"")
}

// TestRunClearWarnsWhenReferenceSurvives verifies that a deleted credential still
// referenced by the configuration file is reported.
func TestRunClearWarnsWhenReferenceSurvives(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		clearResult: app.PasswordClearResult{
			Instance: testInstanceName,
			Service:  testService,
			Key:      testKeyringKey,
			Removed:  true,
			Saved:    false,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(
		t,
		seams,
		"",
		clearCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, "Removed credential")
	assert.Contains(t, run.errOut, "still references it")
}

// TestRunClearRemovesWholeService verifies the service-wide clear and that the
// configuration is deliberately left alone.
func TestRunClearRemovesWholeService(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		clearAllResult: app.PasswordClearResult{
			Service: testService,
			Removed: true,
			All:     true,
		},
	}

	seams := testStreams(store, true, testSecret)

	run := runPassword(
		t,
		seams,
		"y\n",
		clearCommandName,
		"--"+allFlagName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, 0, store.clears)
	assert.Equal(t, 1, store.clearAlls)
	assert.Equal(t, "Removed every credential in service \"agh-cli\".\n", run.out)
	assert.Contains(
		t,
		run.errOut,
		"Remove every credential of the configured service?",
	)
}

// TestRunClearRejectsAmbiguousSelection verifies that the mutually exclusive
// selections are refused before anything is deleted.
func TestRunClearRejectsAmbiguousSelection(t *testing.T) {
	t.Parallel()

	tests := map[string][]string{
		"instance and all": {clearCommandName, testInstanceName, "--" + allFlagName},
		"neither":          {clearCommandName},
	}

	for name, args := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &fakeCoordinator{}
			seams := testStreams(store, true, testSecret)

			run := runPassword(t, seams, "y\n", args...)

			require.ErrorIs(t, run.err, ErrInvalidSelection)
			assert.Equal(t, 0, store.clears)
			assert.Equal(t, 0, store.clearAlls)
		})
	}
}

// TestRunClearDeclinedConfirmationDeletesNothing verifies that a refused prompt
// leaves the credential store untouched.
func TestRunClearDeclinedConfirmationDeletesNothing(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, true, testSecret)

	run := runPassword(
		t,
		seams,
		"no\n",
		clearCommandName,
		testInstanceName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, 0, store.clears)
	assert.Contains(t, run.errOut, "Canceled")
}

// TestRunClearRequiresConfirmationWithoutTerminal verifies that a redirected
// workflow cannot silently delete a credential.
func TestRunClearRequiresConfirmationWithoutTerminal(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runPassword(t, seams, "", clearCommandName, testInstanceName)

	require.ErrorIs(t, run.err, ErrConfirmationUnavailable)
	assert.Equal(t, 0, store.clears)
}

// TestRunClearForwardsExternalSourceRefusal verifies that the external-source
// refusal reaches the operator unchanged.
func TestRunClearForwardsExternalSourceRefusal(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		clearErr: fmt.Errorf(
			"clear credential of %q: %w: source is %q",
			testInstanceName,
			app.ErrExternalCredentialSource,
			"env",
		),
	}

	seams := testStreams(store, false, testSecret)

	run := runPassword(
		t,
		seams,
		"",
		clearCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.ErrorIs(t, run.err, app.ErrExternalCredentialSource)
	assert.Contains(t, run.err.Error(), "env")
}

// TestRunClearForwardsStoreFailure verifies that a store failure reaches the
// operator.
func TestRunClearForwardsStoreFailure(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{clearErr: errors.New("credential store unavailable")}
	seams := testStreams(store, false, testSecret)

	run := runPassword(
		t,
		seams,
		"",
		clearCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "credential store unavailable")
}

// TestRunClearForwardsServiceFailure verifies that a service-wide store failure
// reaches the operator.
func TestRunClearForwardsServiceFailure(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{clearAllErr: errors.New("credential store unavailable")}
	seams := testStreams(store, false, testSecret)

	run := runPassword(
		t,
		seams,
		"",
		clearCommandName,
		"--"+allFlagName,
		"--"+yesFlagName,
	)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "clear credential service")
}
