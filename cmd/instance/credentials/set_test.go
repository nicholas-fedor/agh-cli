// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// failingReader always fails a read.
type failingReader struct{}

// failingWriter always fails a write.
type failingWriter struct{}

// TestRunSetReadsRedirectedSecret verifies the non-interactive write path, the
// confirmation requirement, and that no output stream ever carries the secret.
func TestRunSetReadsRedirectedSecret(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		setResult: app.SetResult{
			Instance: testInstanceName,
			Backend:  testBackend,
			Service:  testService,
			Key:      testKeyringKey,
			Saved:    true,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		testSecret+"\n",
		setCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, 1, store.sets)
	assert.Equal(t, testSecret, store.secret)
	assert.Equal(t, testInstanceName, store.name)
	assert.Empty(t, store.key)
	assert.Equal(
		t,
		"Stored credential for instance \"default\" in keyring service "+
			"\"agh-cli\" with key \"default\".\n",
		run.out,
	)
	assert.NotContains(t, run.out, testSecret)
	assert.NotContains(t, run.errOut, testSecret)
}

// TestRunSetUsesHiddenTerminalPrompt verifies the interactive write path prompts
// on the error stream and never echoes the secret.
func TestRunSetUsesHiddenTerminalPrompt(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		setResult: app.SetResult{
			Instance: testInstanceName,
			Backend:  testBackend,
			Service:  testService,
			Key:      testKeyringKey,
			Saved:    true,
		},
	}

	seams := testStreams(store, true, testSecret)

	run := runCredentials(
		t,
		seams,
		"y\n",
		setCommandName,
		testInstanceName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, testSecret, store.secret)
	assert.Equal(t, 1, store.sets)
	assert.Contains(t, run.errOut, "Password: ")
	assert.Contains(t, run.errOut, "Store this credential for instance \"default\"?")
	assert.NotContains(t, run.errOut, testSecret)
	assert.NotContains(t, run.out, testSecret)
}

// TestRunSetRequiresConfirmationWithoutTerminal verifies that a redirected
// workflow cannot silently store a credential.
func TestRunSetRequiresConfirmationWithoutTerminal(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, testSecret+"\n", setCommandName, testInstanceName)

	require.ErrorIs(t, run.err, ErrConfirmationUnavailable)
	assert.Equal(t, 0, store.sets)
}

// TestRunSetDeclinedConfirmationStoresNothing verifies that a refused prompt
// leaves the credential store untouched.
func TestRunSetDeclinedConfirmationStoresNothing(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, true, testSecret)

	run := runCredentials(
		t,
		seams,
		"n\n",
		setCommandName,
		testInstanceName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, 0, store.sets)
	assert.Contains(t, run.errOut, "Canceled")
	assert.NotContains(t, run.errOut, testSecret)
}

// TestRunSetRejectsEmptySecret verifies that an empty secret never reaches the
// credential store, because it would replace a working password.
func TestRunSetRejectsEmptySecret(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		input    string
		terminal bool
		secret   string
	}{
		"redirected whitespace": {
			input:    "\n",
			terminal: false,
			secret:   testSecret,
		},
		"hidden prompt blank": {
			input:    "y\n",
			terminal: true,
			secret:   "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store := &fakeCoordinator{}
			seams := testStreams(store, test.terminal, test.secret)

			run := runCredentials(
				t,
				seams,
				test.input,
				setCommandName,
				testInstanceName,
				"--"+yesFlagName,
			)

			require.ErrorIs(t, run.err, ErrEmptySecret)
			assert.Equal(t, 0, store.sets)
		})
	}
}

// TestRunSetTrimsSingleTrailingNewline verifies that a piped secret is not
// polluted by the trailing newline of the pipe.
func TestRunSetTrimsSingleTrailingNewline(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		testSecret+"\n",
		setCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, testSecret, store.secret)
}

// TestRunSetKeepsTrailingNewlineOfDoubledRedirect verifies that only the
// transport newline is removed.
func TestRunSetKeepsTrailingNewlineOfDoubledRedirect(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		testSecret+"\n\n",
		setCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, testSecret+"\n", store.secret)
}

// TestRunSetForwardsCustomKey verifies that a custom credential key reaches the
// use case.
func TestRunSetForwardsCustomKey(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		setResult: app.SetResult{
			Instance: testInstanceName,
			Backend:  testBackend,
			Service:  testService,
			Key:      "adguard-production-admin",
			Replaced: true,
			Saved:    true,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		testSecret+"\n",
		setCommandName,
		testInstanceName,
		"--"+keyFlagName, "adguard-production-admin",
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Equal(t, "adguard-production-admin", store.key)
	assert.Contains(t, run.out, "Replaced credential")
	assert.NotContains(t, run.out, testSecret)
}

// TestRunSetWarnsWhenConfigurationWasNotSaved verifies that a stored credential
// with an unsaved configuration is reported on the error stream.
func TestRunSetWarnsWhenConfigurationWasNotSaved(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{
		setResult: app.SetResult{
			Instance: testInstanceName,
			Backend:  testBackend,
			Service:  testService,
			Key:      testKeyringKey,
			Saved:    false,
		},
	}

	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		testSecret+"\n",
		setCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.NoError(t, run.err)
	assert.Contains(t, run.out, "Stored credential")
	assert.Contains(t, run.errOut, "still")
	assert.NotContains(t, run.errOut, testSecret)
}

// TestRunSetForwardsStoreFailure verifies that a store failure reaches the
// operator without disclosing the secret.
func TestRunSetForwardsStoreFailure(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{setErr: errors.New("credential store unavailable")}
	seams := testStreams(store, false, testSecret)

	run := runCredentials(
		t,
		seams,
		testSecret+"\n",
		setCommandName,
		testInstanceName,
		"--"+yesFlagName,
	)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "credential store unavailable")
	assert.Contains(t, run.err.Error(), testInstanceName)
	assert.NotContains(t, run.out, testSecret)
	assert.NotContains(t, run.err.Error(), testSecret)
}

// TestRunSetRequiresInstanceName verifies the published argument arity.
func TestRunSetRequiresInstanceName(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	run := runCredentials(t, seams, testSecret, setCommandName)

	require.Error(t, run.err)
	assert.Equal(t, 0, store.sets)
}

// TestSecretReaderPipedReportsReadFailure verifies that an unreadable input is
// reported instead of storing an empty credential.
func TestSecretReaderPipedReportsReadFailure(t *testing.T) {
	t.Parallel()

	reader := secretReader{in: &failingReader{}}

	_, err := reader.piped()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read secret from standard input")
}

// TestSecretReaderPromptReportsWriteFailure verifies that a failing prompt
// stream is reported instead of silently reading a secret.
func TestSecretReaderPromptReportsWriteFailure(t *testing.T) {
	t.Parallel()

	reader := secretReader{
		in:  strings.NewReader(testSecret),
		out: &failingWriter{},
		readPassword: func(io.Reader) ([]byte, error) {
			return []byte(testSecret), nil
		},
	}

	_, err := reader.prompt()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "write secret prompt")
}

// TestSecretReaderPromptReportsReadFailure verifies that a failing hidden read is
// reported before any credential write.
func TestSecretReaderPromptReportsReadFailure(t *testing.T) {
	t.Parallel()

	reader := secretReader{
		in:  strings.NewReader(testSecret),
		out: &strings.Builder{},
		readPassword: func(io.Reader) ([]byte, error) {
			return nil, errors.New("terminal is unavailable")
		},
	}

	_, err := reader.prompt()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "read secret from terminal")
	assert.NotContains(t, err.Error(), testSecret)
}

// Read always reports a failure.
//
// Parameters:
//   - _ buffer that would receive the read bytes.
//
// Returns:
//   - int: always zero.
//   - error: always a synthetic read failure.
func (*failingReader) Read(_ []byte) (int, error) {
	return 0, errors.New("input is unreadable")
}

// Write always reports a failure.
//
// Parameters:
//   - _ bytes that would be written.
//
// Returns:
//   - int: always zero.
//   - error: always a synthetic write failure.
func (*failingWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("output is unwritable")
}
