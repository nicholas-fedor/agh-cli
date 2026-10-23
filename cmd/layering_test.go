// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package cmd

import (
	"cmp"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io/fs"
	"maps"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// commandPackage is one parsed package of the command layer.
type commandPackage struct {
	// fileSet positions the parsed files.
	fileSet *token.FileSet
	// importPath is the import path the package is checked under.
	importPath string
	// files holds the parsed production files.
	files []*ast.File
}

// violation is one way a command file reaches into a domain package beyond its
// values.
type violation struct {
	// text describes the violation, starting with its position.
	text string
	// pos orders the violation within its package.
	pos token.Pos
}

// modulePath is the import path prefix of this module's packages.
const modulePath = "github.com/nicholas-fedor/agh-cli"

// layeringFixtures is the directory holding the packages that exercise the
// layering checks.
const layeringFixtures = "testdata/layering"

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

	for _, pkg := range commandPackages(t, ".") {
		for _, file := range pkg.files {
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				require.NoError(t, err)

				reason, refused := infrastructurePackages[imported]
				assert.Falsef(
					t, refused, "%s imports %s: %s",
					pkg.fileSet.Position(spec.Pos()).Filename, imported, reason,
				)
			}
		}
	}
}

// TestCommandFilesUseDomainPackagesForValuesOnly verifies that a production
// command file names a domain package only for its values.
//
// A file never refers to a domain function, whether it calls the function or
// keeps it as a value to call later. It never selects a method declared in a
// domain package and never converts a value to a domain type. A dot import of a
// domain package is refused as well, because it hides which names come from the
// package.
func TestCommandFilesUseDomainPackagesForValuesOnly(t *testing.T) {
	t.Parallel()

	packages := commandPackages(t, ".")
	sources := sourceImporter(packages[0].fileSet)

	for _, pkg := range packages {
		for _, text := range domainViolations(t, pkg, sources) {
			assert.Fail(t, "command file reaches into a domain package", text)
		}
	}
}

// TestDomainViolationsRefuseBehavior verifies that each way of reaching domain
// behavior is reported, so the production check cannot pass by missing a form.
func TestDomainViolationsRefuseBehavior(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		fixture string
		want    string
	}{
		"method call": {
			fixture: "method",
			want:    "selects method List of *client.Service",
		},
		"pointer conversion": {
			fixture: "pointerconversion",
			want:    "converts to *client.Settings",
		},
		"function value": {
			fixture: "functionvalue",
			want:    "refers to function credentials.NewManager",
		},
		"dot import": {
			fixture: "dotimport",
			want:    "dot-imports " + modulePath + "/internal/credentials",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			violations := fixtureViolations(t, test.fixture)

			require.Len(t, violations, 1)
			assert.Contains(t, violations[0], test.want)
		})
	}
}

// TestDomainViolationsAllowValues verifies that building and reading domain
// values is not reported.
func TestDomainViolationsAllowValues(t *testing.T) {
	t.Parallel()

	assert.Empty(t, fixtureViolations(t, "values"))
}

// domainViolations type-checks one package and reports every way its files
// reach into a domain package beyond its values.
//
// Parameters:
//   - pkg: parsed command package.
//   - sources: importer that type-checks the package's imports.
//
// Returns:
//   - []string: one description per violation, in source order.
func domainViolations(t *testing.T, pkg commandPackage, sources types.Importer) []string {
	t.Helper()

	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}

	checker := types.Config{Importer: sources}

	_, err := checker.Check(pkg.importPath, pkg.fileSet, pkg.files, info)
	require.NoError(t, err)

	violations := dotImportViolations(t, pkg)

	violations = append(violations, functionViolations(pkg.fileSet, info)...)
	violations = append(violations, methodViolations(pkg.fileSet, info)...)
	violations = append(violations, conversionViolations(pkg, info)...)

	slices.SortFunc(violations, func(left, right violation) int {
		return cmp.Compare(left.pos, right.pos)
	})

	texts := make([]string, 0, len(violations))
	for _, found := range violations {
		texts = append(texts, found.text)
	}

	return texts
}

// functionViolations reports every reference to a domain package function.
//
// Every reference counts, called or not, because a function kept as a value is
// called later through a name the check cannot follow. Resolved references
// cover a renamed or dot import too.
//
// Parameters:
//   - fileSet: positions of the checked files.
//   - info: type information of the checked package.
//
// Returns:
//   - []violation: one violation per reference.
func functionViolations(fileSet *token.FileSet, info *types.Info) []violation {
	var violations []violation

	for ident, object := range info.Uses {
		function, isFunction := object.(*types.Func)
		if !isFunction || function.Signature().Recv() != nil || !isDomainPackage(function.Pkg()) {
			continue
		}

		violations = append(violations, violation{
			text: fmt.Sprintf(
				"%s refers to function %s.%s; reach its behavior through internal/app",
				fileSet.Position(ident.Pos()), function.Pkg().Name(), function.Name(),
			),
			pos: ident.Pos(),
		})
	}

	return violations
}

// methodViolations reports every selection of a method declared in a domain
// package, whether it is called, kept as a method value, or named as a method
// expression.
//
// Parameters:
//   - fileSet: positions of the checked files.
//   - info: type information of the checked package.
//
// Returns:
//   - []violation: one violation per method selection.
func methodViolations(fileSet *token.FileSet, info *types.Info) []violation {
	var violations []violation

	for selector, selection := range info.Selections {
		if selection.Kind() == types.FieldVal || !isDomainPackage(selection.Obj().Pkg()) {
			continue
		}

		violations = append(violations, violation{
			text: fmt.Sprintf(
				"%s selects method %s of %s; reach its behavior through internal/app",
				fileSet.Position(selector.Sel.Pos()), selection.Obj().Name(),
				types.TypeString(selection.Recv(), packageName),
			),
			pos: selector.Sel.Pos(),
		})
	}

	return violations
}

// conversionViolations reports every conversion to a domain type, including a
// conversion to a pointer to one.
//
// Parameters:
//   - pkg: parsed command package.
//   - info: type information of the checked package.
//
// Returns:
//   - []violation: one violation per conversion.
func conversionViolations(pkg commandPackage, info *types.Info) []violation {
	var violations []violation

	for _, file := range pkg.files {
		ast.Inspect(file, func(node ast.Node) bool {
			found, isConversion := conversionViolation(pkg.fileSet, info, node)
			if isConversion {
				violations = append(violations, found)
			}

			return true
		})
	}

	return violations
}

// conversionViolation reports whether one node converts a value to a domain
// type or a pointer to one.
//
// Parameters:
//   - fileSet: positions of the checked files.
//   - info: type information of the checked package.
//   - node: syntax node under inspection.
//
// Returns:
//   - violation: the conversion, when the node is one.
//   - bool: true when the node converts to a domain type.
func conversionViolation(fileSet *token.FileSet, info *types.Info, node ast.Node) (violation, bool) {
	call, isCall := node.(*ast.CallExpr)
	if !isCall {
		return violation{}, false
	}

	target, isTyped := info.Types[call.Fun]
	if !isTyped || !target.IsType() || !isDomainType(target.Type) {
		return violation{}, false
	}

	return violation{
		text: fmt.Sprintf(
			"%s converts to %s; build domain values with composite literals",
			fileSet.Position(call.Pos()), types.TypeString(target.Type, packageName),
		),
		pos: call.Pos(),
	}, true
}

// dotImportViolations reports every dot import of a domain package.
//
// Parameters:
//   - pkg: parsed command package.
//
// Returns:
//   - []violation: one violation per dot import.
func dotImportViolations(t *testing.T, pkg commandPackage) []violation {
	t.Helper()

	var violations []violation

	for _, file := range pkg.files {
		for _, spec := range file.Imports {
			imported, err := strconv.Unquote(spec.Path.Value)
			require.NoError(t, err)

			_, isDomain := domainValuePackages[imported]
			if !isDomain || spec.Name == nil || spec.Name.Name != "." {
				continue
			}

			violations = append(violations, violation{
				text: fmt.Sprintf(
					"%s dot-imports %s, which hides the names it uses from the package",
					pkg.fileSet.Position(spec.Pos()), imported,
				),
				pos: spec.Pos(),
			})
		}
	}

	return violations
}

// isDomainType reports whether a type is a domain type or a pointer to one.
//
// Parameters:
//   - typ: converted-to type.
//
// Returns:
//   - bool: true when the type, after removing pointers, is declared in a
//     domain package.
func isDomainType(typ types.Type) bool {
	for {
		pointer, isPointer := types.Unalias(typ).(*types.Pointer)
		if !isPointer {
			break
		}

		typ = pointer.Elem()
	}

	named, isNamed := types.Unalias(typ).(*types.Named)

	return isNamed && isDomainPackage(named.Obj().Pkg())
}

// isDomainPackage reports whether a package is a domain value package.
//
// Parameters:
//   - pkg: declaring package, or nil for a universe object.
//
// Returns:
//   - bool: true when the package is a domain value package.
func isDomainPackage(pkg *types.Package) bool {
	if pkg == nil {
		return false
	}

	_, isDomain := domainValuePackages[pkg.Path()]

	return isDomain
}

// packageName qualifies a type name by its package name alone, which keeps
// reported types short.
//
// Parameters:
//   - pkg: package that declares a named type.
//
// Returns:
//   - string: the package name.
func packageName(pkg *types.Package) string {
	return pkg.Name()
}

// fixtureViolations reports the violations of one layering fixture package.
//
// Parameters:
//   - fixture: fixture directory name under the layering fixtures.
//
// Returns:
//   - []string: one description per violation, in source order.
func fixtureViolations(t *testing.T, fixture string) []string {
	t.Helper()

	packages := commandPackages(t, path.Join(layeringFixtures, fixture))
	require.Len(t, packages, 1)

	return domainViolations(t, packages[0], sourceImporter(packages[0].fileSet))
}

// sourceImporter returns an importer that type-checks imports from source.
//
// The importer caches every package it checks, so one importer serves every
// package of a single walk. It is not safe for concurrent use, so a parallel
// test builds its own.
//
// Parameters:
//   - fileSet: positions shared with the checked packages.
//
// Returns:
//   - [types.Importer]: the source importer.
func sourceImporter(fileSet *token.FileSet) types.Importer {
	return importer.ForCompiler(fileSet, "source", nil)
}

// commandPackages parses every production Go file under a directory of the
// command layer and groups the files by package.
//
// Parameters:
//   - root: directory to walk, relative to the cmd directory.
//
// Returns:
//   - []commandPackage: the parsed packages ordered by directory.
func commandPackages(t *testing.T, root string) []commandPackage {
	t.Helper()

	fileSet := token.NewFileSet()
	files := make(map[string][]*ast.File)

	for _, filePath := range commandFilePaths(t, root) {
		file, err := parser.ParseFile(fileSet, filePath, nil, parser.SkipObjectResolution)
		require.NoError(t, err)

		dir := filepath.Dir(filePath)

		files[dir] = append(files[dir], file)
	}

	packages := make([]commandPackage, 0, len(files))

	for _, dir := range slices.Sorted(maps.Keys(files)) {
		packages = append(packages, commandPackage{
			fileSet:    fileSet,
			importPath: path.Join(modulePath, "cmd", filepath.ToSlash(dir)),
			files:      files[dir],
		})
	}

	return packages
}

// commandFilePaths lists every production Go file under a directory of the
// command layer.
//
// A testdata directory below the root is skipped, because it holds fixtures
// rather than command files.
//
// Parameters:
//   - root: directory to walk, relative to the cmd directory.
//
// Returns:
//   - []string: the file paths in walk order.
func commandFilePaths(t *testing.T, root string) []string {
	t.Helper()

	var paths []string

	err := filepath.WalkDir(root, func(filePath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}

		if entry.IsDir() {
			return skipFixtures(root, filePath, entry.Name())
		}

		include, err := isCommandFile(filePath)
		if include {
			paths = append(paths, filePath)
		}

		return err
	})
	require.NoError(t, err)
	require.NotEmpty(t, paths)

	return paths
}

// skipFixtures skips a testdata directory below the walked root.
//
// Parameters:
//   - root: directory the walk started from.
//   - dir: directory the walk reached.
//   - name: base name of the reached directory.
//
// Returns:
//   - error: [filepath.SkipDir] for a testdata directory below the root,
//     otherwise nil.
func skipFixtures(root, dir, name string) error {
	if dir != root && name == "testdata" {
		return filepath.SkipDir
	}

	return nil
}

// isCommandFile reports whether a file is a production Go file the build would
// compile, so the check sees the same package the compiler does.
//
// Parameters:
//   - filePath: file the walk reached.
//
// Returns:
//   - bool: true for a non-test Go file that its build constraints include.
//   - error: a wrapped error when the build constraints cannot be read.
func isCommandFile(filePath string) (bool, error) {
	dir, name := filepath.Split(filePath)
	if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
		return false, nil
	}

	matches, err := build.Default.MatchFile(dir, name)
	if err != nil {
		return false, fmt.Errorf("match build constraints of %s: %w", filePath, err)
	}

	return matches, nil
}
