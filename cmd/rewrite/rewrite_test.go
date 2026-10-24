// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
	"github.com/nicholas-fedor/agh-cli/internal/flags"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// rewriteMutationRecorder records rewrite mutation requests in arrival order.
type rewriteMutationRecorder struct {
	// t receives per-request assertions from the test-server handler.
	t *testing.T

	// mutex guards methods against concurrent test-server handlers.
	mutex sync.Mutex

	// methods holds the observed "METHOD path" pairs in arrival order.
	methods []string
}

// rewriteFlagExpectation describes one expected flag registration.
type rewriteFlagExpectation struct {
	// shorthand is the expected one-letter shorthand.
	shorthand string
	// def is the expected default value rendered by pflag.
	def string
}

const (
	// RewriteCommandTestInstance names the single HTTP test instance.
	rewriteCommandTestInstance = "test"
	// RewriteCommandTestDomain is the rewrite domain exercised by command tests.
	rewriteCommandTestDomain = "example.com"
	// RewriteCommandTestAnswer is the rewrite answer exercised by command tests.
	rewriteCommandTestAnswer = "192.0.2.1"
	// RewriteCommandTestSort is the sort column exercised by command tests.
	rewriteCommandTestSort = "domain"
	// RewriteCommandList names the list subcommand.
	RewriteCommandList = "list"
	// RewriteCommandAdd names the add subcommand.
	RewriteCommandAdd = "add"
	// RewriteCommandDelete names the delete subcommand.
	RewriteCommandDelete = "delete"
	// RewriteCommandUpdate names the update subcommand.
	RewriteCommandUpdate = "update"
	// RewriteCommandDiff names the diff subcommand.
	RewriteCommandDiff = "diff"
	// RewriteFlagAll names the shared --all flag.
	RewriteFlagAll = "all"
	// RewriteFlagAnswer names the --answer flag of rewrite deletion.
	RewriteFlagAnswer = "answer"
	// RewriteFlagEnabled names the --enabled flag of rewrite rule mutations.
	RewriteFlagEnabled = "enabled"
	// RewriteFlagFile names the --file flag of rewrite diffs.
	RewriteFlagFile = "file"
	// RewriteFlagInstance names the shared --instance flag.
	RewriteFlagInstance = "instance"
	// RewriteFlagSort names the --sort flag of rewrite listings and diffs.
	RewriteFlagSort = "sort"
	// RewriteDefaultDisabled renders the pflag default of a disabled bool flag.
	RewriteDefaultDisabled = "false"
	// RewriteDefaultEnabled renders the pflag default of an enabled bool flag.
	RewriteDefaultEnabled = "true"
	// RewriteDefaultEmptyList renders the pflag default of an empty string slice.
	RewriteDefaultEmptyList = "[]"
	// RewriteArgAll is the CLI argument targeting every instance.
	RewriteArgAll = "--all"
	// RewriteRouteAdd is the recorded add mutation route.
	RewriteRouteAdd = "POST /control/rewrite/add"
)

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := NewCommand()
	second := NewCommand()

	firstList := requireRewriteSubcommand(t, first, RewriteCommandList)
	secondList := requireRewriteSubcommand(t, second, RewriteCommandList)
	firstDelete := requireRewriteSubcommand(t, first, RewriteCommandDelete)
	secondDelete := requireRewriteSubcommand(t, second, RewriteCommandDelete)

	assert.NotSame(t, firstList, secondList)
	assert.NotSame(t, firstDelete, secondDelete)

	require.NoError(t, firstList.Flags().Set(RewriteFlagAll, RewriteDefaultEnabled))
	require.NoError(t, firstList.Flags().Set(RewriteFlagInstance, "first"))
	require.NoError(t, firstDelete.Flags().Set(RewriteFlagAnswer, "192.0.2.9"))

	assert.True(t, firstList.Flags().Changed(RewriteFlagAll))
	assert.False(t, secondList.Flags().Changed(RewriteFlagAll))

	allFlag, err := secondList.Flags().GetBool(RewriteFlagAll)
	require.NoError(t, err)
	assert.False(t, allFlag)

	names, err := secondList.Flags().GetStringSlice(RewriteFlagInstance)
	require.NoError(t, err)
	assert.Empty(t, names)

	answer, err := secondDelete.Flags().GetString(RewriteFlagAnswer)
	require.NoError(t, err)
	assert.Empty(t, answer)
}

// TestNewCommandBindsDocumentedFlags verifies that every subcommand registers
// exactly the documented flags, shorthands, and defaults.
func TestNewCommandBindsDocumentedFlags(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		// name identifies the subcommand under test.
		name string
		// wantFlags maps flag names to their expected shorthand and default.
		wantFlags map[string]rewriteFlagExpectation
	}{
		{
			name: RewriteCommandList,
			wantFlags: map[string]rewriteFlagExpectation{
				RewriteFlagAll:      {shorthand: "a", def: RewriteDefaultDisabled},
				RewriteFlagInstance: {shorthand: "i", def: RewriteDefaultEmptyList},
				RewriteFlagSort:     {shorthand: "s", def: rewriteCommandTestSort},
			},
		},
		{
			name: RewriteCommandAdd,
			wantFlags: map[string]rewriteFlagExpectation{
				RewriteFlagAll:      {shorthand: "a", def: RewriteDefaultDisabled},
				RewriteFlagEnabled:  {shorthand: "e", def: RewriteDefaultEnabled},
				RewriteFlagInstance: {shorthand: "i", def: RewriteDefaultEmptyList},
			},
		},
		{
			name: RewriteCommandDelete,
			wantFlags: map[string]rewriteFlagExpectation{
				RewriteFlagAll:      {shorthand: "a", def: RewriteDefaultDisabled},
				RewriteFlagAnswer:   {shorthand: "A", def: ""},
				RewriteFlagEnabled:  {shorthand: "e", def: RewriteDefaultEnabled},
				RewriteFlagInstance: {shorthand: "i", def: RewriteDefaultEmptyList},
			},
		},
		{
			name: RewriteCommandUpdate,
			wantFlags: map[string]rewriteFlagExpectation{
				RewriteFlagAll:      {shorthand: "a", def: RewriteDefaultDisabled},
				RewriteFlagEnabled:  {shorthand: "e", def: RewriteDefaultEnabled},
				RewriteFlagInstance: {shorthand: "i", def: RewriteDefaultEmptyList},
			},
		},
		{
			name: RewriteCommandDiff,
			wantFlags: map[string]rewriteFlagExpectation{
				RewriteFlagAll:      {shorthand: "a", def: RewriteDefaultDisabled},
				RewriteFlagFile:     {shorthand: "f", def: ""},
				RewriteFlagInstance: {shorthand: "i", def: RewriteDefaultEmptyList},
				RewriteFlagSort:     {shorthand: "s", def: rewriteCommandTestSort},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			command := requireRewriteSubcommand(t, NewCommand(), testCase.name)

			assert.Equal(
				t,
				slices.Sorted(maps.Keys(testCase.wantFlags)),
				registeredFlagNames(command),
			)

			for flagName, expected := range testCase.wantFlags {
				flag := command.Flags().Lookup(flagName)
				require.NotNilf(t, flag, "flag %q is not registered", flagName)
				assert.Equal(t, expected.shorthand, flag.Shorthand)
				assert.Equal(t, expected.def, flag.DefValue)
			}
		})
	}
}

// TestNewCommandExecutionUsesFreshContext verifies that a later execution never
// observes a context left behind on an earlier command tree.
func TestNewCommandExecutionUsesFreshContext(t *testing.T) {
	t.Parallel()

	observed := make([]error, 0, 2)

	first := NewCommand()
	recordRewriteContext(t, first, &observed)
	first.SetArgs([]string{RewriteCommandList})

	cancelable, cancel := context.WithCancel(t.Context())
	require.NoError(t, first.ExecuteContext(cancelable))

	cancel()

	second := NewCommand()
	recordRewriteContext(t, second, &observed)
	second.SetArgs([]string{RewriteCommandList})

	require.NoError(t, second.Execute())

	require.Len(t, observed, 2)
	assert.NoError(t, observed[0])
	assert.NoError(t, observed[1])
}

// TestNewCommandRepeatedExecutionAppliesRules verifies that repeatedly
// constructing and executing the command tree mutates every target instance.
func TestNewCommandRepeatedExecutionAppliesRules(t *testing.T) {
	t.Parallel()

	recorder := &rewriteMutationRecorder{t: t, methods: make([]string, 0, 2)}
	server := newRewriteCommandServer(t, recorder.serveRewriteMutation)
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	for range 2 {
		command := NewCommand()
		output := &bytes.Buffer{}
		command.SetOut(output)
		command.SetErr(io.Discard)
		command.SetArgs([]string{
			RewriteCommandAdd,
			RewriteArgAll,
			"--" + RewriteFlagEnabled + "=false",
			rewriteCommandTestDomain,
			rewriteCommandTestAnswer,
		})

		require.NoError(t, command.ExecuteContext(ctx))
		assert.Contains(t, output.String(), "Added rewrite rule")
	}

	assert.Equal(t, []string{
		RewriteRouteAdd,
		RewriteRouteAdd,
	}, recorder.recorded())
}

// TestNewCommandDeleteRequiresAnswer verifies that the delete command still
// rejects a missing --answer flag value.
func TestNewCommandDeleteRequiresAnswer(t *testing.T) {
	t.Parallel()

	command := NewCommand()
	command.SetOut(io.Discard)
	command.SetErr(io.Discard)
	command.SetArgs([]string{RewriteCommandDelete, RewriteArgAll, rewriteCommandTestDomain})

	err := command.Execute()
	require.ErrorIs(t, err, flags.ErrAnswerRequired)
}

// TestRunRewriteListUsesAppOutput verifies list command output wiring.
func TestRunRewriteListUsesAppOutput(t *testing.T) {
	t.Parallel()

	server := newRewriteCommandServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/rewrite/list", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`[{"domain":"example.com","answer":"192.0.2.1","enabled":false}]`))
		assert.NoError(t, err)
	})
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	command := newRewriteCommand(ctx)
	output := &bytes.Buffer{}
	command.SetOut(output)

	require.NoError(t, runRewriteList(command, nil, testRewriteListFlags()))
	assert.Contains(t, output.String(), "example.com")
	assert.Contains(t, output.String(), "192.0.2.1")
	assert.Contains(t, output.String(), "disabled")
}

// TestRunRewriteListPreservesStructuredError verifies command error wrapping.
func TestRunRewriteListPreservesStructuredError(t *testing.T) {
	t.Parallel()

	server := newRewriteCommandServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	err := runRewriteList(newRewriteCommand(ctx), nil, testRewriteListFlags())

	gotErr, ok := errors.AsType[*adguard.Error](err)
	require.True(t, ok)
	assert.Equal(t, adguard.ErrorKindStatus, gotErr.Kind)
}

// TestRewriteMutationsUseAppOutput verifies add, delete, and update command wiring.
func TestRewriteMutationsUseAppOutput(t *testing.T) {
	t.Parallel()

	recorder := &rewriteMutationRecorder{t: t, methods: make([]string, 0, 3)}
	server := newRewriteCommandServer(t, recorder.serveRewriteMutation)
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	addCommand := NewCommand()
	addOutput := &bytes.Buffer{}
	addCommand.SetOut(addOutput)
	addCommand.SetErr(io.Discard)
	addCommand.SetArgs([]string{
		RewriteCommandAdd,
		RewriteArgAll,
		"--" + RewriteFlagEnabled + "=false",
		rewriteCommandTestDomain,
		rewriteCommandTestAnswer,
	})
	require.NoError(t, addCommand.ExecuteContext(ctx))

	updateCommand := NewCommand()
	updateOutput := &bytes.Buffer{}
	updateCommand.SetOut(updateOutput)
	updateCommand.SetErr(io.Discard)
	updateCommand.SetArgs([]string{
		RewriteCommandUpdate,
		RewriteArgAll,
		"--" + RewriteFlagEnabled + "=false",
		rewriteCommandTestDomain,
		rewriteCommandTestAnswer,
	})
	require.NoError(t, updateCommand.ExecuteContext(ctx))

	deleteCommand := NewCommand()
	deleteOutput := &bytes.Buffer{}
	deleteCommand.SetOut(deleteOutput)
	deleteCommand.SetErr(io.Discard)
	deleteCommand.SetArgs([]string{
		RewriteCommandDelete,
		RewriteArgAll,
		"--answer=" + rewriteCommandTestAnswer,
		"--" + RewriteFlagEnabled + "=false",
		rewriteCommandTestDomain,
	})
	require.NoError(t, deleteCommand.ExecuteContext(ctx))

	assert.Equal(t, []string{
		RewriteRouteAdd,
		"PUT /control/rewrite/update",
		"POST /control/rewrite/delete",
	}, recorder.recorded())
	assert.Contains(t, addOutput.String(), "Added rewrite rule")
	assert.Contains(t, updateOutput.String(), "Updated rewrite rule")
	assert.Contains(t, deleteOutput.String(), "Deleted rewrite rule")
}

// TestRunRewriteDiffFileUsesAppOutput verifies file diff command wiring.
func TestRunRewriteDiffFileUsesAppOutput(t *testing.T) {
	t.Parallel()

	server := newRewriteCommandServer(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/control/rewrite/list", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")

		_, err := w.Write([]byte(`[{"domain":"remote.example","answer":"192.0.2.2","enabled":true}]`))
		assert.NoError(t, err)
	})
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	path := filepath.Join(t.TempDir(), "rules.yaml")
	contents := []byte("- domain: local.example\n  answer: 192.0.2.1\n  enabled: false\n")
	require.NoError(t, os.WriteFile(path, contents, 0o600))

	values := testRewriteDiffFlags()

	values.File = path

	command := newRewriteCommand(ctx)
	output := &bytes.Buffer{}
	command.SetOut(output)

	require.NoError(t, runRewriteDiff(command, nil, values))
	assert.Contains(t, output.String(), "LOCAL")
	assert.Contains(t, output.String(), "REMOTE")
	assert.Contains(t, output.String(), "local.example")
	assert.Contains(t, output.String(), "remote.example")
}

// registeredFlagNames returns every flag name registered on a command.
//
// Parameters:
//   - command: Command whose local flags are inspected.
//
// Returns:
//   - []string: The registered flag names in sorted order.
func registeredFlagNames(command *cobra.Command) []string {
	names := make([]string, 0)

	command.Flags().VisitAll(func(flag *pflag.Flag) {
		names = append(names, flag.Name)
	})

	slices.Sort(names)

	return names
}

// recorded returns a copy of the observed "METHOD path" pairs.
//
// Returns:
//   - []string: The recorded method and path pairs in arrival order.
func (recorder *rewriteMutationRecorder) recorded() []string {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()

	return append([]string(nil), recorder.methods...)
}

// serveRewriteMutation validates one rewrite mutation request and records it.
//
// Parameters:
//   - writer: Response writer receiving the mutation status code.
//   - request: Incoming HTTP request carrying the mutation payload.
func (recorder *rewriteMutationRecorder) serveRewriteMutation(
	writer http.ResponseWriter,
	request *http.Request,
) {
	recorder.mutex.Lock()

	recorder.methods = append(recorder.methods, request.Method+" "+request.URL.Path)
	recorder.mutex.Unlock()

	body, err := io.ReadAll(request.Body)
	if !assert.NoError(recorder.t, err) {
		writer.WriteHeader(http.StatusBadRequest)

		return
	}

	var decoded map[string]any

	if !assert.NoError(recorder.t, json.Unmarshal(body, &decoded)) {
		writer.WriteHeader(http.StatusBadRequest)

		return
	}

	payload := decoded
	if request.URL.Path == "/control/rewrite/update" {
		update, updateExists := decoded["update"].(map[string]any)
		assert.True(recorder.t, updateExists)

		payload = update

		target, targetExists := decoded["target"].(map[string]any)
		assert.True(recorder.t, targetExists)
		assert.Empty(recorder.t, target)
	}

	assert.Equal(recorder.t, false, payload["enabled"])
	writer.WriteHeader(http.StatusOK)
}

// newRewriteCommandServer starts an HTTP test server for command wiring tests.
//
// Parameters:
//   - handler: Request handler served by the test server.
//
// Returns:
//   - [httptest.Server]: The started HTTP test server.
func newRewriteCommandServer(
	t *testing.T,
	handler http.HandlerFunc,
) *httptest.Server {
	t.Helper()

	server := httptest.NewTestServer(t, handler)
	server.Start()

	return server
}

// newRewriteCommand returns a command bound to ctx.
//
// Parameters:
//   - ctx: Context carrying the configuration of the run.
//
// Returns:
//   - *cobra.Command: The command receiving rewrite output.
func newRewriteCommand(ctx context.Context) *cobra.Command {
	command := &cobra.Command{}
	command.SetContext(ctx)

	return command
}

// testRewriteListFlags returns the list flag values shared by run-function
// tests.
//
// Returns:
//   - *flags.RewriteListFlags: Values targeting every instance with sorting by
//     domain.
func testRewriteListFlags() *flags.RewriteListFlags {
	return &flags.RewriteListFlags{
		Names: nil, All: true,
		Sort: rewriteCommandTestSort,
	}
}

// testRewriteDiffFlags returns the diff flag values shared by run-function
// tests.
//
// Returns:
//   - *flags.RewriteDiffFlags: Values targeting every instance with sorting by
//     domain and no rules file.
func testRewriteDiffFlags() *flags.RewriteDiffFlags {
	return &flags.RewriteDiffFlags{
		Names: nil, All: true,
		File: "",
		Sort: rewriteCommandTestSort,
	}
}

// requireRewriteSubcommand returns the named subcommand of a command tree.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree that owns the subcommand.
//   - name: Subcommand name to look up.
//
// Returns:
//   - *cobra.Command: The located subcommand.
func requireRewriteSubcommand(
	t *testing.T,
	command *cobra.Command,
	name string,
) *cobra.Command {
	t.Helper()

	for _, subcommand := range command.Commands() {
		if subcommand.Name() == name {
			return subcommand
		}
	}

	require.FailNowf(t, "missing subcommand", "subcommand %q is not registered", name)

	return nil
}

// recordRewriteContext replaces the list command body with a context probe.
//
// Parameters:
//   - t: Testing handle receiving assertions.
//   - command: Command tree whose list command is replaced.
//   - observed: Collector receiving the observed context error per execution.
func recordRewriteContext(t *testing.T, command *cobra.Command, observed *[]error) {
	t.Helper()

	listCommand := requireRewriteSubcommand(t, command, "list")

	listCommand.RunE = func(cmd *cobra.Command, _ []string) error {
		*observed = append(*observed, cmd.Context().Err())

		return nil
	}
}

// rewriteCommandContext returns a test context carrying one HTTP test instance.
//
// Parameters:
//   - host: Address of the HTTP test server backing the test instance.
//
// Returns:
//   - [context.Context]: Test context carrying the configured instance.
func rewriteCommandContext(t *testing.T, host string) context.Context {
	t.Helper()

	return apptest.Context(t, fmt.Sprintf(
		"instances:\n  %q:\n    host: %q\n    scheme: http\n",
		rewriteCommandTestInstance,
		host,
	))
}
