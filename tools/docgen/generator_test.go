// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeRenderer records rendered pages and returns configured failures.
type fakeRenderer struct {
	// indexPaths collects the index pages requested for rendering.
	indexPaths []string
	// commandPaths collects the command pages requested for rendering.
	commandPaths []string
	// commandNames collects the documented command names passed for rendering.
	commandNames []string
	// indexErr is returned by RenderIndex when set.
	indexErr error
	// commandErr is returned by RenderCommand when set.
	commandErr error
}

const (
	// Description generated for the agh-cli reference.
	indexDescription = "Complete command reference for agh-cli, organized by functional area."
)

var (
	// Fake index rendering failure used by generator failure tests.
	errFakeIndex = errors.New("index render failed")

	// Fake command rendering failure used by generator failure tests.
	errFakeCommand = errors.New("command render failed")
)

// RenderCommand records a requested command page and its documented name.
//
// Parameters:
//   - doc: The command documentation requested for rendering.
//   - filePath: The output file path requested for rendering.
//
// Returns:
//   - error: The configured command failure.
func (r *fakeRenderer) RenderCommand(doc *CommandDoc, filePath string) error {
	r.commandPaths = append(r.commandPaths, filePath)
	r.commandNames = append(r.commandNames, doc.Name)

	return r.commandErr
}

// RenderIndex records a requested index page.
//
// Parameters:
//   - doc: The index documentation requested for rendering.
//   - filePath: The output file path requested for rendering.
//
// Returns:
//   - error: The configured index failure.
func (r *fakeRenderer) RenderIndex(_ *IndexDoc, filePath string) error {
	r.indexPaths = append(r.indexPaths, filePath)

	return r.indexErr
}

// TestNewDocGeneratorLoadsDefaultDependencies verifies that the default
// generator resolves the bundled templates.
func TestNewDocGeneratorLoadsDefaultDependencies(t *testing.T) {
	t.Parallel()

	generator, err := NewDocGenerator()

	require.NoError(t, err)
	assert.NotNil(t, generator)
}

// TestNewDocGeneratorWithDepsAcceptsDependencies verifies that injected
// dependencies are accepted.
func TestNewDocGeneratorWithDepsAcceptsDependencies(t *testing.T) {
	t.Parallel()

	generator := NewDocGeneratorWithDeps(newCobraExtractor(), &fakeRenderer{})

	require.NotNil(t, generator)
	assert.NotNil(t, generator.extractor)
	assert.NotNil(t, generator.renderer)
}

// TestDocGeneratorGenerateRendersPageTree verifies that every command in the
// tree is rendered to its own section page.
func TestDocGeneratorGenerateRendersPageTree(t *testing.T) {
	t.Parallel()

	outputDir := t.TempDir()
	renderer := &fakeRenderer{}
	generator := NewDocGeneratorWithDeps(newCobraExtractor(), renderer)

	err := generator.Generate(newTestDocumentedTree(), outputDir)

	require.NoError(t, err)
	assert.Equal(
		t,
		[]string{filepath.Join(outputDir, indexPageName)},
		renderer.indexPaths,
	)
	assert.Equal(t, []string{"rewrite", "add", "version"}, renderer.commandNames)
	assert.Equal(
		t,
		[]string{
			filepath.Join(outputDir, "rewrite", indexPageName),
			filepath.Join(outputDir, "rewrite", "add", indexPageName),
			filepath.Join(outputDir, "version", indexPageName),
		},
		renderer.commandPaths,
	)
}

// TestDocGeneratorGenerateWritesRenderedPages verifies that the default
// generator writes the reference pages of a documented command tree.
func TestDocGeneratorGenerateWritesRenderedPages(t *testing.T) {
	t.Parallel()

	outputDir := filepath.Join(t.TempDir(), "cli-reference")
	generator, err := NewDocGenerator()

	require.NoError(t, err)
	require.NoError(t, generator.Generate(newTestDocumentedTree(), outputDir))

	indexPage := filepath.Join(outputDir, indexPageName)
	require.FileExists(t, indexPage)
	require.FileExists(t, filepath.Join(outputDir, "rewrite", indexPageName))
	require.FileExists(t, filepath.Join(outputDir, "rewrite", "add", indexPageName))
	require.FileExists(t, filepath.Join(outputDir, "version", indexPageName))

	index, err := os.ReadFile(indexPage)
	require.NoError(t, err)
	assert.Contains(t, string(index), indexDescription)
	assert.Contains(t, string(index), "/cli-reference/rewrite/add/")

	leafPage, err := os.ReadFile(filepath.Join(outputDir, "rewrite", "add", indexPageName))
	require.NoError(t, err)
	assert.Contains(t, string(leafPage), "agh-cli rewrite add [flags]")
	assert.Contains(t, string(leafPage), "agh-cli rewrite add example.com 192.0.2.1")
}

// TestDocGeneratorGenerateWrapsIndexFailure verifies that index rendering
// failures stop generation and keep their cause.
func TestDocGeneratorGenerateWrapsIndexFailure(t *testing.T) {
	t.Parallel()

	renderer := &fakeRenderer{indexErr: errFakeIndex}
	generator := NewDocGeneratorWithDeps(newCobraExtractor(), renderer)

	err := generator.Generate(newTestDocumentedTree(), t.TempDir())

	require.ErrorIs(t, err, errFakeIndex)
	assert.ErrorContains(t, err, "render index")
}

// TestDocGeneratorGenerateWrapsCommandFailure verifies that command rendering
// failures stop generation and name the failing section.
func TestDocGeneratorGenerateWrapsCommandFailure(t *testing.T) {
	t.Parallel()

	renderer := &fakeRenderer{commandErr: errFakeCommand}
	generator := NewDocGeneratorWithDeps(newCobraExtractor(), renderer)

	err := generator.Generate(newTestDocumentedTree(), t.TempDir())

	require.ErrorIs(t, err, errFakeCommand)
	assert.ErrorContains(t, err, "render command rewrite")
}

// TestDocGeneratorGenerateRejectsUnusableOutputDirectory verifies that an
// output path below a regular file is reported instead of written.
func TestDocGeneratorGenerateRejectsUnusableOutputDirectory(t *testing.T) {
	t.Parallel()

	occupied := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(occupied, []byte("occupied"), filePerms))

	generator := NewDocGeneratorWithDeps(newCobraExtractor(), &fakeRenderer{})

	err := generator.Generate(newTestDocumentedTree(), filepath.Join(occupied, "cli-reference"))

	require.Error(t, err)
	assert.ErrorContains(t, err, "create output directory")
}

// newTestDocumentedTree builds the command tree documented by generator tests.
//
// Returns:
//   - *cobra.Command: The root command with a group and a leaf command.
func newTestDocumentedTree() *cobra.Command {
	root := newTestRootCommand()
	root.AddCommand(
		newTestGroupCommand(),
		newTestRunnableCommand("version", "Print the application version"),
	)

	return root
}
