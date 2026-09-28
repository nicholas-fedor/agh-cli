// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"bytes"
	"context"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// fakeCoordinator records the migration request and returns the configured
// outcome.
type fakeCoordinator struct {
	// report is the outcome returned by Migrate.
	report app.MigrationReport
	// migrateErr is the error returned by Migrate.
	migrateErr error
	// dryRun records the dry-run selection handed to Migrate.
	dryRun bool
	// migrations counts the Migrate calls made by the command.
	migrations int
}

// commandRun captures the rendered result of one command execution.
type commandRun struct {
	// out is the command output stream.
	out string
	// errOut is the command error stream.
	errOut string
	// err is the execution error.
	err error
}

// credentialsCommandName is the published name of the credentials command.
const credentialsCommandName = "credentials"

// migrateCommandName is the published name of the migrate subcommand.
const migrateCommandName = "migrate"

// usernameCommandName is the published name of the username subcommand group.
const usernameCommandName = "username"

// passwordCommandName is the published name of the password subcommand group.
const passwordCommandName = "password"

// testInstanceName is the instance name used by the command tests.
const testInstanceName = "default"

// testSecret is the password used by the command tests.
const testSecret = "s3cr3t-adguard-password"

// testService is the credential store namespace used by the command tests.
const testService = "agh-cli"

// testBackend is the credential store backend name used by the command tests.
const testBackend = "keyring"

// testKeyringKey is the credential key used by the command tests.
const testKeyringKey = "default"

// errTestFactory is the coordinator construction failure the command tests inject.
var errTestFactory = errors.New("no configuration file")

// allowedProductionImports is the complete set of third-party and project
// imports the production command files may use.
//
// The package renders a report and hands a migration request to the application
// layer. Configuration loading and credential policy belong there, so these files
// must never name the configuration package, the credential store package, or the
// instance domain package. The two subpackages are listed because this package
// composes them, and the composition is the only import either one earns here.
var allowedProductionImports = map[string]struct{}{
	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials/password": {},
	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials/username": {},
	"github.com/nicholas-fedor/agh-cli/internal/app":                      {},
	"github.com/spf13/cobra": {},
	"golang.org/x/term":      {},
}

// forbiddenProductionImports names the packages the command files must not
// depend on, with the reason each dependency is refused.
var forbiddenProductionImports = map[string]string{
	"github.com/nicholas-fedor/agh-cli/internal/config":      "configuration loading belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/credentials": "credential policy belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/instance":    "instance policy belongs to internal/app",
	"github.com/spf13/viper":                                 "the command reads no Viper key",
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

// testStreams builds input seams over an injected coordinator.
//
// Parameters:
//   - store: coordinator returned by the command.
//
// Returns:
//   - *streams: test dependencies for the credentials commands.
func testStreams(store coordinator) *streams {
	return &streams{
		coordinator: func() (coordinator, error) {
			return store, nil
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

// TestNewCommandPreservesGroupSyntax verifies the published CLI surface of the
// credentials command group.
func TestNewCommandPreservesGroupSyntax(t *testing.T) {
	t.Parallel()

	group := NewCommand()

	assert.Equal(t, credentialsCommandName, group.Use)
	assert.Equal(t, "Manage instance authentication", group.Short)

	migrate := requireLeaf(t, group, migrateCommandName)
	assert.Equal(t, "migrate", migrate.Use)

	assert.Equal(t, "username", requireLeaf(t, group, usernameCommandName).Use)
	assert.Equal(t, "password", requireLeaf(t, group, passwordCommandName).Use)
}

// TestNewCommandBuildsIndependentTrees verifies that repeated construction
// returns distinct commands whose flag values never leak between trees.
func TestNewCommandBuildsIndependentTrees(t *testing.T) {
	t.Parallel()

	first := NewCommand()
	second := NewCommand()

	assert.NotSame(t, first, second)
	assert.NotSame(t, requireLeaf(t, first, migrateCommandName),
		requireLeaf(t, second, migrateCommandName))
}

// TestMigrateDryRunFlagIsBound verifies the migration preview flag is published.
func TestMigrateDryRunFlagIsBound(t *testing.T) {
	t.Parallel()

	migrate := requireLeaf(t, NewCommand(), migrateCommandName)

	flag := migrate.Flags().Lookup(dryRunFlagName)
	require.NotNil(t, flag)
	assert.Equal(t, "false", flag.DefValue)
}

// TestNewCommandRejectsProductionConfigurationError verifies a coordinator
// failure names the failing step.
func TestNewCommandRejectsProductionConfigurationError(t *testing.T) {
	t.Parallel()

	group := newCommandGroup(&streams{
		coordinator: func() (coordinator, error) {
			return nil, errTestFactory
		},
	})

	group.SetOut(&bytes.Buffer{})
	group.SetErr(&bytes.Buffer{})
	group.SetArgs([]string{migrateCommandName})

	err := group.Execute()

	require.ErrorIs(t, err, errTestFactory)
	assert.Contains(t, err.Error(), "build credential coordinator")
}

// TestProductionFilesImportOnlyAppLayer verifies that every production command
// file, in this package and in both subpackages, depends on the application layer
// and nothing below it.
func TestProductionFilesImportOnlyAppLayer(t *testing.T) {
	t.Parallel()

	forEachProductionFile(t, func(t *testing.T, name string, imports []string) {
		t.Helper()

		for _, imported := range imports {
			if strings.HasPrefix(imported, "github.com/nicholas-fedor/agh-cli/internal/") {
				assert.Equal(t, "github.com/nicholas-fedor/agh-cli/internal/app", imported, name)
			}
		}
	})
}

// TestProductionFilesAvoidInternalPackages verifies that no production command
// file imports a package the command layer must not depend on.
func TestProductionFilesAvoidInternalPackages(t *testing.T) {
	t.Parallel()

	forEachProductionFile(t, func(t *testing.T, name string, imports []string) {
		t.Helper()

		for _, imported := range imports {
			reason, forbidden := forbiddenProductionImports[imported]
			assert.Falsef(t, forbidden, "%s must not import %s: %s", name, imported, reason)
		}
	})
}

// forEachProductionFile applies check to every non-test Go file in this package
// and in both subpackages.
//
// The subpackages are walked because they hold the bulk of the command surface,
// and a boundary enforced only at the parent would not cover them.
//
// Parameters:
//   - t: active test requiring the file walk.
//   - check: assertion applied to each parsed import list.
func forEachProductionFile(
	t *testing.T,
	check func(t *testing.T, name string, imports []string),
) {
	t.Helper()

	for _, dir := range []string{".", "username", "password"} {
		for _, path := range productionFiles(t, dir) {
			check(t, path, fileImports(t, path))
		}
	}
}

// productionFiles returns the non-test Go files in one directory.
//
// Parameters:
//   - t: active test requiring the directory read.
//   - dir: directory holding the command files.
//
// Returns:
//   - []string: paths of the non-test Go files in the directory.
func productionFiles(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	paths := make([]string, 0, len(entries))

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
			strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}

		paths = append(paths, filepath.Join(dir, entry.Name()))
	}

	return paths
}

// fileImports parses the import paths of one file.
//
// Parameters:
//   - t: active test requiring the parse.
//   - path: file whose imports are read.
//
// Returns:
//   - []string: the parsed import paths.
func fileImports(t *testing.T, path string) []string {
	t.Helper()

	parsed, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	require.NoError(t, err)

	imports := make([]string, 0, len(parsed.Imports))

	for _, spec := range parsed.Imports {
		imported, unquoteErr := strconv.Unquote(spec.Path.Value)
		require.NoError(t, unquoteErr)

		imports = append(imports, imported)
	}

	return imports
}

// assertAllowedImports verifies the imports of one file against the allow-list.
//
// Parameters:
//   - t: active test requiring the assertion.
//   - name: file whose imports are checked.
//   - imports: parsed import paths of the file.
func assertAllowedImports(t *testing.T, name string, imports []string) {
	t.Helper()

	for _, imported := range imports {
		if strings.HasPrefix(imported, "github.com/nicholas-fedor/agh-cli/") ||
			strings.HasPrefix(imported, "github.com/spf13/") ||
			strings.HasPrefix(imported, "golang.org/x/") {
			_, allowed := allowedProductionImports[imported]
			assert.Truef(t, allowed, "%s imports %s, which is not on the allow-list", name, imported)
		}
	}
}

// TestProductionFilesUseOnlyAllowListedImports verifies that every production
// command file stays inside the documented import boundary.
func TestProductionFilesUseOnlyAllowListedImports(t *testing.T) {
	t.Parallel()

	forEachProductionFile(t, assertAllowedImports)
}
