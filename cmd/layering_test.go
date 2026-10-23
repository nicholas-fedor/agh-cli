// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// commandSource is one parsed production file of the command layer.
type commandSource struct {
	// path is the file path relative to the cmd directory.
	path string
	// fileSet positions the parsed file.
	fileSet *token.FileSet
	// file is the parsed file.
	file *ast.File
}

// domainExports are the exported package-level functions and types of one
// domain package.
type domainExports struct {
	// functions holds the exported function names.
	functions map[string]struct{}
	// types holds the exported type names.
	types map[string]struct{}
}

// modulePath is the import path prefix of this module's packages.
const modulePath = "github.com/nicholas-fedor/agh-cli"

// domainValuePackages are the domain packages whose value types the command
// layer may name. Their behavior is reached only through internal/app, so a
// command file may build and read their values but never call into them.
var domainValuePackages = map[string]struct{}{
	"github.com/nicholas-fedor/agh-cli/internal/client":      {},
	"github.com/nicholas-fedor/agh-cli/internal/credentials": {},
	"github.com/nicholas-fedor/agh-cli/internal/filtering":   {},
	"github.com/nicholas-fedor/agh-cli/internal/rewrite":     {},
}

// infrastructurePackages are the packages the command layer must never import,
// with the reason each is refused.
var infrastructurePackages = map[string]string{
	"github.com/nicholas-fedor/agh-cli/internal/config":     "configuration loading belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/connection": "client construction belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/execution":  "multi-instance execution belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/internal/instance":   "instance policy belongs to internal/app",
	"github.com/nicholas-fedor/agh-cli/pkg/adguard":         "AdGuard Home is reached through internal/app",
}

// TestCommandFilesAvoidInfrastructurePackages verifies that no production
// command file imports a package whose behavior belongs to internal/app.
func TestCommandFilesAvoidInfrastructurePackages(t *testing.T) {
	t.Parallel()

	for _, source := range commandSources(t) {
		for _, spec := range source.file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			require.NoError(t, err)

			reason, refused := infrastructurePackages[imported]
			assert.Falsef(t, refused, "%s imports %s: %s", source.path, imported, reason)
		}
	}
}

// TestCommandFilesUseDomainPackagesForValuesOnly verifies that a production
// command file names a domain package only for its values.
//
// A file never refers to a domain function, whether it calls the function or
// keeps it as a value to call later, and never converts a value to a domain
// type. A dot import of a domain package is refused as well, because it hides
// which names come from the package.
func TestCommandFilesUseDomainPackagesForValuesOnly(t *testing.T) {
	t.Parallel()

	exports := loadDomainExports(t)

	for _, source := range commandSources(t) {
		for _, violation := range domainViolations(t, source, exports) {
			assert.Fail(t, "command file reaches into a domain package", violation)
		}
	}
}

// domainViolations reports every way a file reaches into a domain package
// beyond its values.
//
// Parameters:
//   - source: parsed command file.
//   - exports: exported names of every domain package, keyed by import path.
//
// Returns:
//   - []string: one description per violation, in file order.
func domainViolations(
	t *testing.T,
	source commandSource,
	exports map[string]domainExports,
) []string {
	t.Helper()

	packages, violations := domainImportNames(t, source)

	ast.Inspect(source.file, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.SelectorExpr:
			violations = appendDomainFunction(violations, source, typed, packages, exports)
		case *ast.CallExpr:
			violations = appendDomainConversion(violations, source, typed, packages, exports)
		default:
			// Every other node only leads to the selectors and calls below it.
		}

		return true
	})

	return violations
}

// appendDomainFunction records a reference to a domain package function.
//
// Every reference counts, called or not, because a function kept as a value is
// called later through a name the check cannot follow.
//
// Parameters:
//   - violations: violations found so far.
//   - source: parsed command file.
//   - selector: selector expression under inspection.
//   - packages: domain import paths keyed by the name the file uses for them.
//   - exports: exported names of every domain package, keyed by import path.
//
// Returns:
//   - []string: violations with the reference appended when it names a domain
//     function.
func appendDomainFunction(
	violations []string,
	source commandSource,
	selector *ast.SelectorExpr,
	packages map[string]string,
	exports map[string]domainExports,
) []string {
	imported, isDomain := domainPackage(selector, packages)
	if !isDomain {
		return violations
	}

	if _, isFunction := exports[imported].functions[selector.Sel.Name]; !isFunction {
		return violations
	}

	return append(violations, fmt.Sprintf(
		"%s refers to function %s.%s; reach its behavior through internal/app",
		source.fileSet.Position(selector.Pos()), path.Base(imported), selector.Sel.Name,
	))
}

// appendDomainConversion records a conversion to a domain package type.
//
// Parameters:
//   - violations: violations found so far.
//   - source: parsed command file.
//   - call: call expression under inspection.
//   - packages: domain import paths keyed by the name the file uses for them.
//   - exports: exported names of every domain package, keyed by import path.
//
// Returns:
//   - []string: violations with the conversion appended when the call converts
//     to a domain type.
func appendDomainConversion(
	violations []string,
	source commandSource,
	call *ast.CallExpr,
	packages map[string]string,
	exports map[string]domainExports,
) []string {
	selector, isSelector := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !isSelector {
		return violations
	}

	imported, isDomain := domainPackage(selector, packages)
	if !isDomain {
		return violations
	}

	if _, isType := exports[imported].types[selector.Sel.Name]; !isType {
		return violations
	}

	return append(violations, fmt.Sprintf(
		"%s converts to %s.%s; build domain values with composite literals",
		source.fileSet.Position(call.Pos()), path.Base(imported), selector.Sel.Name,
	))
}

// domainPackage reports which domain package a selector selects through.
//
// A local declaration resolves its identifier, so a variable that shares a
// package name is not mistaken for the package.
//
// Parameters:
//   - selector: selector expression under inspection.
//   - packages: domain import paths keyed by the name the file uses for them.
//
// Returns:
//   - string: the import path of the selected domain package.
//   - bool: true when the selector selects through a domain package.
func domainPackage(selector *ast.SelectorExpr, packages map[string]string) (string, bool) {
	receiver, isIdent := selector.X.(*ast.Ident)
	if !isIdent || receiver.Obj != nil {
		return "", false
	}

	imported, isDomain := packages[receiver.Name]

	return imported, isDomain
}

// loadDomainExports reads the exported package-level functions and types of
// every domain package from its source.
//
// Returns:
//   - map[string]domainExports: exported names keyed by import path.
func loadDomainExports(t *testing.T) map[string]domainExports {
	t.Helper()

	exports := make(map[string]domainExports, len(domainValuePackages))

	for imported := range domainValuePackages {
		dir := filepath.Join("..", filepath.FromSlash(strings.TrimPrefix(imported, modulePath+"/")))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)

		names := domainExports{functions: map[string]struct{}{}, types: map[string]struct{}{}}

		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") ||
				strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}

			file, parseErr := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, entry.Name()), nil, 0)
			require.NoError(t, parseErr)

			collectExports(file, names)
		}

		exports[imported] = names
	}

	return exports
}

// collectExports adds the exported package-level functions and types of one
// file.
//
// Parameters:
//   - file: parsed domain package file.
//   - names: exported names collected so far, extended in place.
func collectExports(file *ast.File, names domainExports) {
	for _, declaration := range file.Decls {
		switch typed := declaration.(type) {
		case *ast.FuncDecl:
			if typed.Recv == nil && typed.Name.IsExported() {
				names.functions[typed.Name.Name] = struct{}{}
			}
		case *ast.GenDecl:
			collectTypes(typed, names)
		default:
			// A bad declaration names nothing the command layer could use.
		}
	}
}

// collectTypes adds the exported types of one general declaration.
//
// Parameters:
//   - declaration: parsed general declaration.
//   - names: exported names collected so far, extended in place.
func collectTypes(declaration *ast.GenDecl, names domainExports) {
	for _, spec := range declaration.Specs {
		typeSpec, isType := spec.(*ast.TypeSpec)
		if isType && typeSpec.Name.IsExported() {
			names.types[typeSpec.Name.Name] = struct{}{}
		}
	}
}

// commandSources parses every production Go file under the cmd directory.
//
// Returns:
//   - []commandSource: the parsed files in walk order.
func commandSources(t *testing.T) []commandSource {
	t.Helper()

	var sources []commandSource

	err := filepath.WalkDir(".", func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() || !strings.HasSuffix(filePath, ".go") ||
			strings.HasSuffix(filePath, "_test.go") {
			return nil
		}

		fileSet := token.NewFileSet()

		file, parseErr := parser.ParseFile(fileSet, filePath, nil, 0)
		if parseErr != nil {
			return parseErr
		}

		sources = append(sources, commandSource{path: filePath, fileSet: fileSet, file: file})

		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, sources)

	return sources
}

// domainImportNames returns the names under which a file imports domain
// packages, and refuses a dot import of one.
//
// Parameters:
//   - source: parsed command file.
//
// Returns:
//   - map[string]string: import paths keyed by the name the file uses for them.
//   - []string: one violation per dot import of a domain package.
func domainImportNames(t *testing.T, source commandSource) (map[string]string, []string) {
	t.Helper()

	names := make(map[string]string)

	var violations []string

	for _, spec := range source.file.Imports {
		imported, err := strconv.Unquote(spec.Path.Value)
		require.NoError(t, err)

		if _, isDomain := domainValuePackages[imported]; !isDomain {
			continue
		}

		name := path.Base(imported)
		if spec.Name != nil {
			name = spec.Name.Name
		}

		if name == "." {
			violations = append(violations, fmt.Sprintf(
				"%s dot-imports %s, which hides the names it uses from the package",
				source.fileSet.Position(spec.Pos()), imported,
			))

			continue
		}

		names[name] = imported
	}

	return names, violations
}
