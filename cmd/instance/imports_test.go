// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowedProductionImports is the complete set of third-party and project
// imports the production command files may use.
//
// The command layer defines Cobra commands and renders their output. Loading a
// configuration and reaching a credential store are application concerns, so the
// command files must never name the configuration package, the credential store
// package, or any other project package. The check runs over the production
// files only, because the test files read configuration documents on purpose.
var allowedProductionImports = map[string]struct{}{
	"github.com/nicholas-fedor/agh-cli/cmd/instance/credentials": {},
	"github.com/nicholas-fedor/agh-cli/internal/app":             {},
	"github.com/spf13/cobra":                                     {},
}

// forbiddenProductionImports names the packages the command layer must not
// depend on, with the reason each dependency is refused.
var forbiddenProductionImports = map[string]string{
	"github.com/nicholas-fedor/agh-cli/internal/config":      "load-mutate-save belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/credentials": "credential policy belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/instance":    "instance policy belongs to internal/app",
	"github.com/spf13/viper":                                 "the command reads no Viper key",
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

	files := productionSources(t, ".")
	require.NotEmpty(t, files)

	for name, imports := range files {
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
		if !isProductionSource(entry) {
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

// isProductionSource reports whether a directory entry is a production Go file.
//
// Parameters:
//   - entry: directory entry to classify.
//
// Returns:
//   - bool: true when the entry is a non-test Go file.
func isProductionSource(entry os.DirEntry) bool {
	if entry.IsDir() {
		return false
	}

	name := entry.Name()

	return strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
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
