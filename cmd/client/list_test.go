// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
)

// clientSelectionCase describes one execution of the client list command.
type clientSelectionCase struct {
	// wantErr reports whether the execution is expected to fail.
	wantErr bool
	// args are the command-line arguments of the execution.
	args []string
	// name labels the subtest.
	name string
}

// clientRecorder records client request payloads in arrival order.
type clientRecorder struct {
	// t receives per-request assertions from the test-server handler.
	t *testing.T

	// mutex guards payloads against concurrent test-server handlers.
	mutex sync.Mutex

	// requests counts every served request.
	requests int

	// payloads holds the decoded request bodies in arrival order.
	payloads []map[string]any
}

// record decodes and stores one mutation request body.
//
// Parameters:
//   - request: Incoming HTTP request carrying the payload.
//
// Returns:
//   - bool: false when the request body cannot be decoded.
func (recorder *clientRecorder) record(request *http.Request) bool {
	body, err := io.ReadAll(request.Body)
	if !assert.NoError(recorder.t, err) {
		return false
	}

	var decoded map[string]any

	if !assert.NoError(recorder.t, json.Unmarshal(body, &decoded)) {
		return false
	}

	recorder.mutex.Lock()

	recorder.payloads = append(recorder.payloads, decoded)
	recorder.mutex.Unlock()

	return true
}

// recorded returns a copy of the recorded request payloads.
//
// Returns:
//   - []map[string]any: The recorded request payloads in arrival order.
func (recorder *clientRecorder) recorded() []map[string]any {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()

	return slices.Clone(recorder.payloads)
}

// requestCount returns the number of served requests.
//
// Returns:
//   - int: The number of served requests.
func (recorder *clientRecorder) requestCount() int {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()

	return recorder.requests
}

// serve records one mutation request and answers every request.
//
// Parameters:
//   - writer: Response writer receiving the canned payload.
//   - request: Incoming HTTP request carrying the recorded payload.
func (recorder *clientRecorder) serve(
	writer http.ResponseWriter,
	request *http.Request,
) {
	recorder.mutex.Lock()

	recorder.requests++
	recorder.mutex.Unlock()

	if request.URL.Path == clientCommandListClientsPath {
		writer.Header().Set("Content-Type", "application/json")

		_, err := writer.Write([]byte(clientCommandListClientsPayload))
		assert.NoError(recorder.t, err)

		return
	}

	if !recorder.record(request) {
		writer.WriteHeader(http.StatusBadRequest)

		return
	}

	writer.WriteHeader(http.StatusOK)
}

// TestListReturnsInstanceFailure verifies that client list fails when an instance
// request fails.
func TestListReturnsInstanceFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(
		func(writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusUnauthorized)
		},
	))
	server.Start()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configHost := strings.TrimPrefix(server.URL, "http://")
	configData := fmt.Appendf(
		nil,
		"instances:\n  %s:\n    host: %q\n    scheme: http\n",
		clientCommandAlphaInstance,
		configHost,
	)
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))

	ctx := apptest.FileContext(t, configPath)

	command := NewCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{clientCommandListName, clientCommandAllArg})

	err := command.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorContains(t, err, "401")
}

// TestNewCommandRepeatedExecutionReadsOwnSelection verifies that each execution
// resolves its selection from its own freshly constructed command.
//
// The final execution targets an unconfigured instance name. A selection value
// left over from the first execution would resolve that name through --all and
// succeed instead of failing.
//
//nolint:paralleltest,contextcheck // Ordered subtests share one recorder. Commands read the ExecuteContext context.
func TestNewCommandRepeatedExecutionReadsOwnSelection(t *testing.T) {
	recorder := &clientRecorder{t: t, payloads: make([]map[string]any, 0, 2)}
	server := httptest.NewTestServer(t, http.HandlerFunc(recorder.serve))
	server.Start()

	ctx := clientCommandContext(t, server.Listener.Addr().String())

	cases := []clientSelectionCase{
		{
			name: "every instance",
			args: []string{clientCommandListName, clientCommandAllArg},
		},
		{
			name: "named instance",
			args: []string{
				clientCommandListName,
				clientCommandInstanceArg,
				clientCommandAlphaInstance,
			},
		},
		{
			name:    "unconfigured instance is not masked by a leaked all flag",
			args:    []string{clientCommandListName, clientCommandInstanceArg, clientCommandZuluInstance},
			wantErr: true,
		},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			output := &bytes.Buffer{}
			command := NewCommand()
			command.SetOut(output)
			command.SetErr(io.Discard)
			command.SetArgs(test.args)

			err := command.ExecuteContext(ctx)
			if test.wantErr {
				require.ErrorContains(t, err, clientCommandZuluInstance)

				return
			}

			require.NoError(t, err)
			assert.Contains(t, output.String(), clientCommandListClientName)
			assert.Contains(t, output.String(), clientCommandListAutoClientName)
		})
	}

	// Only the first two executions reach the instance; the third resolves no
	// target and never sends a request.
	assert.Equal(t, 2, recorder.requestCount())
	assert.Empty(t, recorder.recorded())
}

// TestNewCommandRepeatedExecutionSendsOwnMutationFlags verifies that repeated
// executions send only the mutation flags parsed by the current execution.
//
// A shared mutation flag value would leak --filtering from the first execution
// into every later request.
func TestNewCommandRepeatedExecutionSendsOwnMutationFlags(t *testing.T) {
	t.Parallel()

	recorder := &clientRecorder{t: t, payloads: make([]map[string]any, 0, 3)}
	server := httptest.NewTestServer(t, http.HandlerFunc(recorder.serve))
	server.Start()

	ctx := clientCommandContext(t, server.Listener.Addr().String())

	selections := [][]string{
		{clientCommandAddName, clientCommandAllArg, "--id=192.0.2.10", "--filtering", clientCommandListClientName},
		{clientCommandAddName, clientCommandAllArg, "--id=192.0.2.11", "--parental", clientCommandListClientName},
		{clientCommandAddName, clientCommandAllArg, "--id=192.0.2.12", clientCommandListClientName},
	}

	for _, arguments := range selections {
		output := &bytes.Buffer{}
		command := NewCommand()
		command.SetOut(output)
		command.SetErr(io.Discard)
		command.SetArgs(arguments)

		require.NoError(t, command.ExecuteContext(ctx))
		assert.Contains(t, output.String(), "Added client desk")
	}

	payloads := recorder.recorded()
	require.Len(t, payloads, len(selections))

	assert.Equal(t, true, payloads[0]["filtering_enabled"])
	assert.NotContains(t, payloads[0], "parental_enabled")
	assert.Equal(t, true, payloads[1]["parental_enabled"])
	assert.NotContains(t, payloads[1], "filtering_enabled")
	assert.NotContains(t, payloads[2], "filtering_enabled")
	assert.NotContains(t, payloads[2], "parental_enabled")
	assert.Equal(t, true, payloads[2]["use_global_settings"])
}

// TestNewCommandRepeatedExecutionUsesFreshContext verifies that an execution
// after a canceled execution still reaches the instance.
//
// A command retaining the canceled context of an earlier execution would fail
// the later mutation before any request is sent.
func TestNewCommandRepeatedExecutionUsesFreshContext(t *testing.T) {
	t.Parallel()

	recorder := &clientRecorder{t: t, payloads: make([]map[string]any, 0, 2)}
	server := httptest.NewTestServer(t, http.HandlerFunc(recorder.serve))
	server.Start()

	ctx := clientCommandContext(t, server.Listener.Addr().String())

	first := NewCommand()
	firstOutput := &bytes.Buffer{}
	first.SetOut(firstOutput)
	first.SetErr(io.Discard)
	first.SetArgs([]string{clientCommandDeleteName, clientCommandAllArg, clientCommandListClientName})

	cancelable, cancel := context.WithCancel(ctx)
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := NewCommand()
	secondOutput := &bytes.Buffer{}
	second.SetOut(secondOutput)
	second.SetErr(io.Discard)
	second.SetArgs([]string{clientCommandDeleteName, clientCommandAllArg, clientCommandListClientName})

	require.NoError(t, second.ExecuteContext(ctx))

	require.ErrorIs(t, cancelable.Err(), context.Canceled)
	assert.Contains(t, firstOutput.String(), "Deleted client desk")
	assert.Contains(t, secondOutput.String(), "Deleted client desk")
	assert.Len(t, recorder.recorded(), 2)
}

// clientCommandContext returns a test context carrying one HTTP test instance.
//
// Parameters:
//   - host: Address of the HTTP test server backing the test instance.
//
// Returns:
//   - [context.Context]: Test context carrying the configured instance.
func clientCommandContext(t *testing.T, host string) context.Context {
	t.Helper()

	return apptest.Context(t, fmt.Sprintf(
		"instances:\n  %q:\n    host: %q\n    scheme: http\n",
		clientCommandAlphaInstance,
		host,
	))
}
