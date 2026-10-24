// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// filteringExpectedFlag describes one published flag of a filtering subcommand.
type filteringExpectedFlag struct {
	// Shorthand is the published one-letter shorthand.
	Shorthand string
	// Usage is the published help text.
	Usage string
	// Default is the published default rendering.
	Default string
	// ValueType is the published flag value type.
	ValueType string
	// Name is the published flag name.
	Name string
}

// filteringSubcommandSyntax describes the published syntax of one subcommand.
type filteringSubcommandSyntax struct {
	// Flags lists every published flag of the subcommand.
	Flags []filteringExpectedFlag
	// Short is the published one-line description.
	Short string
	// Use is the published invocation syntax.
	Use string
}

// filteringRecorder stands in for one AdGuard Home instance and records every
// request it receives.
type filteringRecorder struct {
	// t receives per-request assertions from the test-server handler.
	t *testing.T
	// host is the test server address the configuration points at.
	host string
	// response is the body written on every reply, or empty for none.
	response string
	// requests holds the observed requests in arrival order.
	requests []filteringRequest
	// mutex guards requests against concurrent test-server handlers.
	mutex sync.Mutex
	// status is the HTTP status code written on every reply.
	status int
}

// filteringRequest is one request a filteringRecorder observed.
type filteringRequest struct {
	// Body is the decoded JSON body, or nil when the request had none.
	Body map[string]any
	// Route is the request method and path, such as "GET /control/status".
	Route string
}

// filteringRun captures the rendered result of one command execution.
type filteringRun struct {
	// err is the execution error.
	err error
	// out is the command output stream.
	out string
	// errOut is the command error stream.
	errOut string
}

// filteringSyntaxCase pairs one subcommand with its published syntax.
type filteringSyntaxCase struct {
	// expected is the published syntax the subcommand must expose.
	expected filteringSubcommandSyntax
	// sub is the subcommand name resolved from a fresh filtering command.
	sub string
	// name labels the subtest.
	name string
}

const (
	// FilteringCommandAlphaInstance identifies the first rendering result.
	filteringCommandAlphaInstance = "alpha"
	// FilteringCommandBoolType identifies the published pflag boolean type.
	filteringCommandBoolType = "bool"
	// FilteringCommandAllFlagArg is the published long form of the --all flag.
	filteringCommandAllFlagArg = "--all"
	// FilteringCommandInstanceFlagArg is the published long form of the
	// --instance flag.
	filteringCommandInstanceFlagArg = "--instance"
	// FilteringCommandStatusName identifies the status subcommand.
	filteringCommandStatusName = "status"
	// FilteringCommandConfigName identifies the config subcommand.
	filteringCommandConfigName = "config"
	// FilteringCommandAddURLName identifies the add-url subcommand.
	filteringCommandAddURLName = "add-url"
	// FilteringCommandRemoveURLName identifies the remove-url subcommand.
	filteringCommandRemoveURLName = "remove-url"
	// FilteringAllFlag names the flag selecting every configured instance.
	filteringAllFlag = "all"
	// FilteringInstanceFlag names the flag selecting explicit instance names.
	filteringInstanceFlag = "instance"
	// FilteringCommandZuluInstance identifies the second configured instance.
	filteringCommandZuluInstance = "zulu"
	// FilteringCommandFilterName is the subscription name the tests send.
	filteringCommandFilterName = "Example list"
	// FilteringCommandFilterURL is the subscription location the tests send.
	filteringCommandFilterURL = "https://filters.example/list.txt"
)

// TestRunFilteringMutationsReportPartialFailure verifies that a mutation over
// every instance writes the result of each instance that succeeded, and that
// the failure of another instance reaches the operator with its structured
// error and the command's context.
func TestRunFilteringMutationsReportPartialFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		success string
		prefix  string
		args    []string
	}{
		{
			name:    "config",
			args:    []string{filteringCommandConfigName},
			success: "[alpha] Filtering config updated: enabled=true, interval=0",
			prefix:  "update filtering config",
		},
		{
			name:    "add-url",
			args:    []string{filteringCommandAddURLName, filteringCommandFilterName, filteringCommandFilterURL},
			success: "[alpha] Added filter URL " + filteringCommandFilterName,
			prefix:  "run filtering add-url",
		},
		{
			name:    "remove-url",
			args:    []string{filteringCommandRemoveURLName, filteringCommandFilterURL},
			success: "[alpha] Removed filter URL " + filteringCommandFilterURL,
			prefix:  "remove filtering URL",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			alpha := newFilteringRecorder(t, http.StatusOK, "")
			zulu := newFilteringRecorder(t, http.StatusInternalServerError, "")
			ctx := filteringCommandContext(t, alpha, zulu)

			run := runFiltering(ctx, t, append(test.args, filteringCommandAllFlagArg)...)

			require.Error(t, run.err)
			assert.Contains(t, run.err.Error(), test.prefix)
			assert.Contains(t, run.err.Error(), filteringCommandZuluInstance)

			gotErr, ok := errors.AsType[*adguard.Error](run.err)
			require.True(t, ok)
			assert.Equal(t, adguard.ErrorKindStatus, gotErr.Kind)

			assert.Contains(t, run.out, test.success+"\n")
			assert.Len(t, alpha.recorded(), 1)
			assert.Len(t, zulu.recorded(), 1)
		})
	}
}

// TestNewCommandPreservesSubcommandSyntax verifies the published CLI surface.
func TestNewCommandPreservesSubcommandSyntax(t *testing.T) {
	t.Parallel()

	for _, test := range filteringSyntaxCases() {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			command := filteringCommand(t, test.sub)

			assert.Equal(t, test.expected.Use, command.Use)
			assert.Equal(t, test.expected.Short, command.Short)
			assertFilteringFlagSyntax(t, command, test.expected.Flags)
		})
	}
}

// TestNewCommandReturnsIndependentSubcommands verifies that repeated construction
// yields separate commands whose parsed flag state cannot leak into a later
// construction or execution.
func TestNewCommandReturnsIndependentSubcommands(t *testing.T) {
	t.Parallel()

	first := filteringCommand(t, filteringCommandStatusName)
	second := filteringCommand(t, filteringCommandStatusName)

	require.NotSame(t, first, second)
	require.NoError(t, first.ParseFlags(
		filteringAllInstancesArguments(filteringCommandAlphaInstance),
	))

	all, err := second.Flags().GetBool(filteringAllFlag)
	require.NoError(t, err)

	names, err := second.Flags().GetStringSlice(filteringInstanceFlag)
	require.NoError(t, err)

	assert.False(t, all)
	assert.Empty(t, names)
}

// filteringCommand returns a freshly constructed filtering subcommand.
//
// Parameters:
//   - t: Test context used to report resolution failures.
//   - name: Subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The freshly constructed subcommand.
func filteringCommand(t *testing.T, name string) *cobra.Command {
	t.Helper()

	command, _, err := NewCommand().Find([]string{name})
	require.NoError(t, err)

	return command
}

// newFilteringRecorder starts a test server that answers every request with one
// status and body.
//
// Parameters:
//   - status: HTTP status code written on every reply.
//   - response: body written on every reply, or empty for none.
//
// Returns:
//   - *filteringRecorder: the recorder serving the started test server.
func newFilteringRecorder(t *testing.T, status int, response string) *filteringRecorder {
	t.Helper()

	recorder := &filteringRecorder{
		t:        t,
		host:     "",
		response: response,
		requests: nil,
		mutex:    sync.Mutex{},
		status:   status,
	}
	server := httptest.NewTestServer(t, http.HandlerFunc(recorder.serve))
	server.Start()

	recorder.host = server.Listener.Addr().String()

	return recorder
}

// filteringCommandContext returns a command context whose configuration points
// the alpha and zulu instances at their recorders.
//
// Parameters:
//   - alpha: recorder standing in for the alpha instance.
//   - zulu: recorder standing in for the zulu instance.
//
// Returns:
//   - [context.Context]: context carrying the loaded configuration.
func filteringCommandContext(t *testing.T, alpha, zulu *filteringRecorder) context.Context {
	t.Helper()

	return apptest.Context(t, fmt.Sprintf(
		"instances:\n  %q:\n    host: %q\n    scheme: http\n  %q:\n    host: %q\n    scheme: http\n",
		filteringCommandAlphaInstance, alpha.host,
		filteringCommandZuluInstance, zulu.host,
	))
}

// runFiltering executes one freshly constructed filtering command tree.
//
// Parameters:
//   - ctx: context carrying the loaded configuration.
//   - args: command line arguments passed to the filtering command.
//
// Returns:
//   - filteringRun: the rendered output streams and the execution error.
//
//nolint:contextcheck // The command reads the context passed to ExecuteContext.
func runFiltering(ctx context.Context, t *testing.T, args ...string) filteringRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := NewCommand()
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetArgs(args)

	err := command.ExecuteContext(ctx)

	return filteringRun{err: err, out: output.String(), errOut: errorsOut.String()}
}

// filteringSelectionFlagSyntax returns the selection flags shared by every
// filtering subcommand.
//
// Returns:
//   - []filteringExpectedFlag: The published shared selection flags.
func filteringSelectionFlagSyntax() []filteringExpectedFlag {
	return []filteringExpectedFlag{
		{
			Name:      filteringAllFlag,
			Shorthand: "a",
			Usage:     "target all instances",
			Default:   "false",
			ValueType: filteringCommandBoolType,
		},
		{
			Name:      filteringInstanceFlag,
			Shorthand: "i",
			Usage:     "target instance name(s)",
			Default:   "[]",
			ValueType: "stringSlice",
		},
	}
}

// filteringSyntaxCases returns the published syntax of every filtering subcommand.
//
// Returns:
//   - []filteringSyntaxCase: One case per published subcommand.
func filteringSyntaxCases() []filteringSyntaxCase {
	selection := filteringSelectionFlagSyntax()

	return []filteringSyntaxCase{
		{
			name: "status",
			sub:  filteringCommandStatusName,
			expected: filteringSubcommandSyntax{
				Use:   filteringCommandStatusName,
				Short: "Get filtering status",
				Flags: filteringFlags(nil, selection),
			},
		},
		{
			name: "config",
			sub:  filteringCommandConfigName,
			expected: filteringSubcommandSyntax{
				Use:   filteringCommandConfigName,
				Short: "Update filtering configuration",
				Flags: filteringFlags([]filteringExpectedFlag{
					{
						Name:      "enabled",
						Shorthand: "e",
						Usage:     "enable filtering",
						Default:   "true",
						ValueType: filteringCommandBoolType,
					},
					{
						Name:      "interval",
						Shorthand: "n",
						Usage:     "update interval hours",
						Default:   "0",
						ValueType: "int32",
					},
				}, selection),
			},
		},
		{
			name: "add-url",
			sub:  filteringCommandAddURLName,
			expected: filteringSubcommandSyntax{
				Use:   "add-url <name> <url>",
				Short: "Add a filter URL",
				Flags: filteringFlags([]filteringExpectedFlag{
					{
						Name:      "whitelist",
						Shorthand: "w",
						Usage:     "add to whitelist",
						Default:   "false",
						ValueType: filteringCommandBoolType,
					},
				}, selection),
			},
		},
		{
			name: "remove-url",
			sub:  filteringCommandRemoveURLName,
			expected: filteringSubcommandSyntax{
				Use:   "remove-url <url>",
				Short: "Remove a filter URL",
				Flags: filteringFlags(nil, selection),
			},
		},
	}
}

// filteringAllInstancesArguments renders arguments selecting every instance.
//
// Parameters:
//   - names: Instance names selected explicitly alongside the --all flag.
//
// Returns:
//   - []string: Flag arguments parsed by a filtering subcommand.
func filteringAllInstancesArguments(names ...string) []string {
	return slices.Concat(
		[]string{filteringCommandAllFlagArg},
		filteringNamedInstancesArguments(names...),
	)
}

// filteringNamedInstancesArguments renders arguments selecting explicit instances.
//
// Parameters:
//   - names: Instance names selected explicitly.
//
// Returns:
//   - []string: Flag arguments parsed by a filtering subcommand.
func filteringNamedInstancesArguments(names ...string) []string {
	arguments := make([]string, 0, 2*len(names))

	for _, name := range names {
		arguments = append(arguments, filteringCommandInstanceFlagArg, name)
	}

	return arguments
}

// filteringFlags assembles the published flags of one subcommand.
//
// Parameters:
//   - command: Command-specific flags published before the shared flags.
//   - shared: Selection flags shared by every filtering subcommand.
//
// Returns:
//   - []filteringExpectedFlag: The assembled published flag descriptions.
func filteringFlags(
	command []filteringExpectedFlag,
	shared []filteringExpectedFlag,
) []filteringExpectedFlag {
	return append(slices.Clone(command), shared...)
}

// assertFilteringFlagSyntax verifies the published flag set of one command.
//
// Parameters:
//   - t: Test context used to report assertion failures.
//   - command: Command whose local flags are verified.
//   - expected: Published flag descriptions.
func assertFilteringFlagSyntax(
	t *testing.T,
	command *cobra.Command,
	expected []filteringExpectedFlag,
) {
	t.Helper()

	registered := make([]string, 0, len(expected))

	command.Flags().VisitAll(func(flag *pflag.Flag) {
		registered = append(registered, flag.Name)
	})

	expectedNames := make([]string, 0, len(expected))
	for _, want := range expected {
		expectedNames = append(expectedNames, want.Name)
	}

	slices.Sort(registered)
	slices.Sort(expectedNames)

	require.Equal(t, expectedNames, registered)

	for _, want := range expected {
		flag := command.Flags().Lookup(want.Name)
		require.NotNilf(t, flag, "flag %q is not registered", want.Name)
		assert.Equal(t, want.Shorthand, flag.Shorthand)
		assert.Equal(t, want.Usage, flag.Usage)
		assert.Equal(t, want.Default, flag.DefValue)
		assert.Equal(t, want.ValueType, flag.Value.Type())
	}
}

// recorded returns a copy of the observed requests.
//
// Returns:
//   - []filteringRequest: the observed requests in arrival order.
func (recorder *filteringRecorder) recorded() []filteringRequest {
	recorder.mutex.Lock()
	defer recorder.mutex.Unlock()

	return slices.Clone(recorder.requests)
}

// serve records one request and writes the configured reply.
//
// Parameters:
//   - writer: response writer receiving the configured reply.
//   - request: incoming HTTP request to record.
func (recorder *filteringRecorder) serve(writer http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(request.Body)
	assert.NoError(recorder.t, err)

	var decoded map[string]any

	if len(body) > 0 {
		assert.NoError(recorder.t, json.Unmarshal(body, &decoded))
	}

	recorder.mutex.Lock()

	recorder.requests = append(recorder.requests, filteringRequest{
		Body:  decoded,
		Route: request.Method + " " + request.URL.Path,
	})
	recorder.mutex.Unlock()

	if recorder.response != "" {
		writer.Header().Set("Content-Type", "application/json")
	}

	writer.WriteHeader(recorder.status)

	_, err = io.WriteString(writer, recorder.response)
	assert.NoError(recorder.t, err)
}
