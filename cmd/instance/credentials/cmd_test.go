// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// fakeCoordinator records the use-case calls made by one command execution.
type fakeCoordinator struct {
	// setResult is the outcome returned by Set.
	setResult app.SetResult
	// setErr is the error returned by Set.
	setErr error
	// clearResult is the outcome returned by Clear.
	clearResult app.ClearResult
	// clearErr is the error returned by Clear.
	clearErr error
	// clearAllResult is the outcome returned by ClearAll.
	clearAllResult app.ClearResult
	// clearAllErr is the error returned by ClearAll.
	clearAllErr error
	// statusResult is the outcome returned by Status.
	statusResult app.StatusResult
	// statusErr is the error returned by Status.
	statusErr error
	// report is the outcome returned by Migrate.
	report app.MigrationReport
	// migrateErr is the error returned by Migrate.
	migrateErr error
	// secret records the secret handed to Set.
	secret string
	// key records the credential key handed to Set.
	key string
	// name records the instance name handed to Set, Clear, or Status.
	name string
	// names records the instance names handed to Status.
	names []string
	// dryRun records the dry-run selection handed to Migrate.
	dryRun bool
	// clears counts the Clear calls made by the command.
	clears int
	// clearAlls counts the ClearAll calls made by the command.
	clearAlls int
	// sets counts the Set calls made by the command.
	sets int
	// migrations counts the Migrate calls made by the command.
	migrations int
}

// commandRun captures the rendered result of one command execution.
type commandRun struct {
	// out is the rendered command output.
	out string
	// errOut is the rendered error output, including prompts and notices.
	errOut string
	// err is the execution error, or nil when the command succeeded.
	err error
}

// credentialsCommandName is the published group name.
const credentialsCommandName = "credentials"

// setCommandName identifies the set subcommand.
const setCommandName = "set"

// clearCommandName identifies the clear subcommand.
const clearCommandName = "clear"

// statusCommandName identifies the status subcommand.
const statusCommandName = "status"

// migrateCommandName identifies the migrate subcommand.
const migrateCommandName = "migrate"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testSecret is the secret supplied by the command tests.
const testSecret = "s3cr3t-adguard-password"

// testService is the credential service used by the command tests.
const testService = "agh-cli"

// testKeyringKey is the credential key used by the command tests.
const testKeyringKey = "default"

// testBackend is the credential store backend used by the command tests.
const testBackend = "keyring"

// testCredentialFile is the mounted secret path used by the command tests.
const testCredentialFile = "/run/secrets/adguard"

// testCredentialEnv is the environment variable used by the command tests.
const testCredentialEnv = "ADGUARD_PASSWORD"

// allowedProductionImports is the complete set of third-party and project
// imports the production command files may use.
//
// The package reads a secret and renders a report. Configuration loading and
// credential policy belong to the application layer, so these files must never
// name the configuration package, the credential store package, or the instance
// domain package.
var allowedProductionImports = map[string]struct{}{
	"github.com/nicholas-fedor/agh-cli/internal/app": {},
	"github.com/spf13/cobra":                         {},
	"golang.org/x/term":                              {},
}

// forbiddenProductionImports names the packages the command files must not
// depend on, with the reason each dependency is refused.
var forbiddenProductionImports = map[string]string{
	"github.com/nicholas-fedor/agh-cli/internal/config":      "configuration loading belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/credentials": "credential policy belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/instance":    "instance policy belongs to internal/app",
	"github.com/spf13/viper":                                 "the command reads no Viper key",
}

// Clear records the request and returns the configured outcome.
func (f *fakeCoordinator) Clear(_ context.Context, name string) (app.ClearResult, error) {
	f.clears++

	f.name = name

	return f.clearResult, f.clearErr
}

// ClearAll records the request and returns the configured outcome.
func (f *fakeCoordinator) ClearAll(_ context.Context) (app.ClearResult, error) {
	f.clearAlls++

	return f.clearAllResult, f.clearAllErr
}

// Migrate records the request and returns the configured outcome.
func (f *fakeCoordinator) Migrate(
	_ context.Context,
	request app.MigrationRequest,
) (app.MigrationReport, error) {
	f.migrations++

	f.dryRun = request.DryRun

	return f.report, f.migrateErr
}

// Set records the request, including the secret, and returns the configured
// outcome.
func (f *fakeCoordinator) Set(
	_ context.Context,
	name, key, secret string,
) (app.SetResult, error) {
	f.sets++

	f.name = name

	f.key = key

	f.secret = secret

	return f.setResult, f.setErr
}

// Status records the request and returns the configured outcome.
func (f *fakeCoordinator) Status(
	_ context.Context,
	names []string,
) (app.StatusResult, error) {
	f.names = names

	return f.statusResult, f.statusErr
}

// testStreams builds input seams over an injected coordinator.
//
// The terminal probe and the hidden reader are fakes, so the tests exercise both
// input shapes without a controlling terminal.
//
// Parameters:
//   - store: coordinator returned by the command.
//   - terminal: reports whether the command input is a terminal.
//   - secret: secret returned by the hidden reader.
//
// Returns:
//   - *streams: test dependencies for the credentials commands.
func testStreams(store coordinator, terminal bool, secret string) *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return store, nil
		},
		isTerminal: func(io.Reader) bool {
			return terminal
		},
		readPassword: func(io.Reader) ([]byte, error) {
			return []byte(secret), nil
		},
	}
}

// runCredentials executes one freshly constructed credentials command tree.
//
// Parameters:
//   - t: active test requiring command construction.
//   - s: input seams and credential coordinator factory.
//   - input: standard input supplied to the command.
//   - args: command line arguments passed to the credentials command.
//
// Returns:
//   - commandRun: the rendered output streams and the execution error.
func runCredentials(
	t *testing.T,
	s *streams,
	input string,
	args ...string,
) commandRun {
	t.Helper()

	output := &bytes.Buffer{}
	errorsOut := &bytes.Buffer{}
	command := newCommandGroup(s)
	command.SetOut(output)
	command.SetErr(errorsOut)
	command.SetIn(strings.NewReader(input))
	command.SetArgs(args)

	err := command.Execute()

	return commandRun{
		out:    output.String(),
		errOut: errorsOut.String(),
		err:    err,
	}
}

// requireLeaf resolves one subcommand of the credentials group.
//
// Parameters:
//   - t: active test requiring command resolution.
//   - group: credentials command owning the subcommand.
//   - name: subcommand name to resolve.
//
// Returns:
//   - *cobra.Command: The resolved subcommand.
func requireLeaf(t *testing.T, group *cobra.Command, name string) *cobra.Command {
	t.Helper()

	command, _, err := group.Find([]string{name})
	require.NoError(t, err)
	require.Equal(t, name, command.Name())

	return command
}

// TestNewCommandPreservesLeafSyntax verifies the published CLI surface of the
// credentials command group.
func TestNewCommandPreservesLeafSyntax(t *testing.T) {
	t.Parallel()

	group := NewCommand()

	assert.Equal(t, credentialsCommandName, group.Use)
	assert.Equal(t, "Manage stored instance credentials", group.Short)

	leaves := map[string]string{
		setCommandName:     "set <name>",
		clearCommandName:   "clear <name>",
		statusCommandName:  "status [name]",
		migrateCommandName: "migrate",
	}

	for name, use := range leaves {
		leaf := requireLeaf(t, group, name)
		assert.Equal(t, use, leaf.Use)
	}
}

// TestSetPublishesNoPasswordFlag verifies that a secret can never reach the
// credential store through the command line.
func TestSetPublishesNoPasswordFlag(t *testing.T) {
	t.Parallel()

	set := requireLeaf(t, NewCommand(), setCommandName)

	assert.Nil(t, set.Flags().Lookup("password"))
	assert.Nil(t, set.Flags().Lookup("pass"))
	assert.NotNil(t, set.Flags().Lookup(keyFlagName))
	assert.NotNil(t, set.Flags().Lookup(yesFlagName))
}

// TestSetFlagShorthandMatchesDocumentation verifies the published -y shorthand.
func TestSetFlagShorthandMatchesDocumentation(t *testing.T) {
	t.Parallel()

	yes := requireLeaf(t, NewCommand(), setCommandName).Flags().Lookup(yesFlagName)
	require.NotNil(t, yes)

	assert.Equal(t, "y", yes.Shorthand)
	assert.Equal(t, "false", yes.DefValue)
}

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	store := &fakeCoordinator{}
	seams := testStreams(store, false, testSecret)

	first := newCommandGroup(seams)
	second := newCommandGroup(seams)

	firstSet := requireLeaf(t, first, setCommandName)
	secondSet := requireLeaf(t, second, setCommandName)

	require.NotSame(t, first, second)
	require.NotSame(t, firstSet, secondSet)

	require.NoError(t, firstSet.Flags().Set(keyFlagName, "leaked"))

	key, err := secondSet.Flags().GetString(keyFlagName)
	require.NoError(t, err)
	assert.Empty(t, key)
	assert.False(t, secondSet.Flags().Changed(keyFlagName))
}

// TestStatusMachineReadableFlagIsBound verifies the published --json flag.
func TestStatusMachineReadableFlagIsBound(t *testing.T) {
	t.Parallel()

	json := requireLeaf(t, NewCommand(), statusCommandName).Flags().Lookup(jsonFlagName)
	require.NotNil(t, json)

	assert.Equal(t, "false", json.DefValue)
	assert.Empty(t, json.Shorthand)
}

// TestMigrateDryRunFlagIsBound verifies the published --dry-run flag.
func TestMigrateDryRunFlagIsBound(t *testing.T) {
	t.Parallel()

	dryRun := requireLeaf(t, NewCommand(), migrateCommandName).Flags().Lookup(dryRunFlagName)
	require.NotNil(t, dryRun)

	assert.Equal(t, "false", dryRun.DefValue)
}

// TestNewCommandRejectsProductionConfigurationError verifies that a coordinator
// that cannot be built fails the command instead of reporting a success.
func TestNewCommandRejectsProductionConfigurationError(t *testing.T) {
	t.Parallel()

	broken := &streams{
		coordinator: func() (coordinator, error) {
			return nil, errors.New("configuration is unreadable")
		},
		isTerminal: func(io.Reader) bool { return false },
		readPassword: func(io.Reader) ([]byte, error) {
			return nil, errors.New("unused")
		},
	}

	run := runCredentials(t, broken, testSecret+"\n", statusCommandName)

	require.Error(t, run.err)
	assert.Contains(t, run.err.Error(), "configuration is unreadable")
}

// TestProductionFilesImportOnlyAppLayer verifies the dependency direction of the
// production command files.
func TestProductionFilesImportOnlyAppLayer(t *testing.T) {
	t.Parallel()

	forEachProductionFile(t, assertAllowedImports)
}

// TestProductionFilesAvoidInternalPackages verifies that the production command
// files never reach into a project package the command layer must not own.
func TestProductionFilesAvoidInternalPackages(t *testing.T) {
	t.Parallel()

	forEachProductionFile(t, assertNoForbiddenImports)
}

// forEachProductionFile runs one assertion over every production source file.
//
// Parameters:
//   - t: active test requiring the package sources.
//   - assertion: check applied to the imports of one production file.
func forEachProductionFile(
	t *testing.T,
	assertion func(t *testing.T, name string, imports []string),
) {
	t.Helper()

	for name, imports := range productionSources(t, ".") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			assertion(t, name, imports)
		})
	}
}

// assertAllowedImports verifies that one file imports only the allowed set.
func assertAllowedImports(t *testing.T, name string, imports []string) {
	t.Helper()

	for _, imported := range imports {
		if isStandardLibrary(imported) {
			continue
		}

		_, allowed := allowedProductionImports[imported]
		assert.Truef(
			t,
			allowed,
			"%s imports %s, which is outside the allowed set",
			name,
			imported,
		)
	}
}

// assertNoForbiddenImports verifies that one file avoids the refused packages.
func assertNoForbiddenImports(t *testing.T, name string, imports []string) {
	t.Helper()

	for _, imported := range imports {
		reason, forbidden := forbiddenProductionImports[imported]
		assert.Falsef(t, forbidden, "%s imports %s: %s", name, imported, reason)
	}
}

// productionSources returns the import paths of every production file in dir.
//
// Parameters:
//   - t: active test requiring the package sources.
//   - dir: directory holding the package files.
//
// Returns:
//   - map[string][]string: production file name mapped to its import paths.
func productionSources(t *testing.T, dir string) map[string][]string {
	t.Helper()

	fileSet := token.NewFileSet()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	sources := make(map[string][]string, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {

			continue
		}

		path := filepath.Join(dir, entry.Name())

		file, parseErr := parser.ParseFile(fileSet, path, nil, parser.ImportsOnly)
		require.NoErrorf(t, parseErr, "parse %s", path)

		imports := make([]string, 0, len(file.Imports))
		for _, spec := range file.Imports {
			imports = append(imports, strings.Trim(spec.Path.Value, `"`))
		}

		sources[entry.Name()] = imports
	}

	return sources
}

// isStandardLibrary reports whether an import path names the standard library.
//
// The first path element of a standard library import never contains a dot,
// which is the same test the go tooling applies.
//
// Parameters:
//   - imported: import path to classify.
//
// Returns:
//   - bool: true when the import names the standard library.
func isStandardLibrary(imported string) bool {
	root, _, _ := strings.Cut(imported, "/")

	return !strings.Contains(root, ".")
}
