// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewHugoRendererLoadsTemplates verifies that the bundled page templates
// are parsed successfully.
func TestNewHugoRendererLoadsTemplates(t *testing.T) {
	t.Parallel()

	renderer, err := newHugoRenderer()

	require.NoError(t, err)
	assert.NotNil(t, renderer)
}

// TestHugoRendererRenderCommandWritesPage verifies that the command template
// emits front matter, usage, examples, and flag tables.
func TestHugoRendererRenderCommandWritesPage(t *testing.T) {
	t.Parallel()

	renderer, err := newHugoRenderer()
	require.NoError(t, err)

	pagePath := filepath.Join(t.TempDir(), "add.md")

	err = renderer.RenderCommand(newTestCommandDoc(), pagePath)

	require.NoError(t, err)

	page, err := os.ReadFile(pagePath)
	require.NoError(t, err)

	rendered := string(page)
	assert.Contains(t, rendered, "title: Add")
	assert.Contains(t, rendered, "type: docs")
	assert.Contains(t, rendered, "### Usage")
	assert.Contains(t, rendered, "agh-cli rewrite add [flags]")
	assert.Contains(t, rendered, "#### Add a rule")
	assert.Contains(t, rendered, "agh-cli rewrite add example.com 192.0.2.1")
	assert.Contains(t, rendered, "### Command Options")
	assert.Contains(t, rendered, "| `--instance` | `-i` | \"\" | string | target instance name |")
	assert.Contains(t, rendered, "### Global Options")
	assert.Contains(t, rendered, "| `--config` | `-c` | \"\" | string | config path |")
}

// TestHugoRendererRenderCommandOmitsEmptySections verifies that a command
// without flags, examples, or a long description omits those sections.
func TestHugoRendererRenderCommandOmitsEmptySections(t *testing.T) {
	t.Parallel()

	renderer, err := newHugoRenderer()
	require.NoError(t, err)

	pagePath := filepath.Join(t.TempDir(), "version.md")

	err = renderer.RenderCommand(&CommandDoc{Title: "Version"}, pagePath)

	require.NoError(t, err)

	page, err := os.ReadFile(pagePath)
	require.NoError(t, err)

	rendered := string(page)
	assert.Contains(t, rendered, "title: Version")
	assert.NotContains(t, rendered, "### Usage")
	assert.NotContains(t, rendered, "### Examples")
	assert.NotContains(t, rendered, "### Command Options")
	assert.NotContains(t, rendered, "### Global Options")
}

// TestHugoRendererRenderIndexWritesPage verifies that the index template emits
// front matter and one table row per documented command.
func TestHugoRendererRenderIndexWritesPage(t *testing.T) {
	t.Parallel()

	renderer, err := newHugoRenderer()
	require.NoError(t, err)

	pagePath := filepath.Join(t.TempDir(), indexPageName)
	index := &IndexDoc{
		Title:       indexTitle,
		Description: indexDescription,
		Sections: []sectionEntry{
			{
				Name:        "rewrite",
				Title:       testGroupShort,
				Description: "Manage DNS rewrite rules.",
				HasSubs:     true,
				SubCommands: []subCommandEntry{
					{
						Name:        "add",
						Description: testCommandShort,
						URL:         "/cli-reference/rewrite/add/",
					},
				},
			},
		},
	}

	err = renderer.RenderIndex(index, pagePath)

	require.NoError(t, err)

	page, err := os.ReadFile(pagePath)
	require.NoError(t, err)

	rendered := string(page)
	assert.Contains(t, rendered, "title: CLI Reference")
	assert.Contains(t, rendered, indexDescription)
	assert.Contains(t, rendered, "## "+testGroupShort)
	assert.Contains(
		t,
		rendered,
		"| [add](/cli-reference/rewrite/add/) | "+testCommandShort+" |",
	)
}

// TestHugoRendererRenderCommandReportsTemplateFailure verifies that template
// execution failures name the rendered page.
func TestHugoRendererRenderCommandReportsTemplateFailure(t *testing.T) {
	t.Parallel()

	renderer, err := newHugoRenderer()
	require.NoError(t, err)

	pagePath := filepath.Join(t.TempDir(), "broken.md")

	err = renderer.RenderCommand(nil, pagePath)

	require.ErrorContains(t, err, "execute template for "+pagePath)
	assert.NoFileExists(t, pagePath)
}

// TestHugoRendererRenderCommandReportsWriteFailure verifies that an
// unwritable destination is reported instead of silently ignored.
func TestHugoRendererRenderCommandReportsWriteFailure(t *testing.T) {
	t.Parallel()

	renderer, err := newHugoRenderer()
	require.NoError(t, err)

	pagePath := filepath.Join(t.TempDir(), "missing", "add.md")

	err = renderer.RenderCommand(newTestCommandDoc(), pagePath)

	require.Error(t, err)
	assert.ErrorContains(t, err, "write file "+pagePath)
}

// TestFormatDefaultValueQuotesEmptyStrings verifies that empty string defaults
// are quoted and every other default is preserved.
func TestFormatDefaultValueQuotesEmptyStrings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		doc  FlagDoc
		want string
	}{
		{
			name: "empty string default is quoted",
			doc:  FlagDoc{Type: "string", Default: ""},
			want: `""`,
		},
		{
			name: "string default is preserved",
			doc:  FlagDoc{Type: "string", Default: "agh-cli.yaml"},
			want: "agh-cli.yaml",
		},
		{
			name: "empty boolean default is preserved",
			doc:  FlagDoc{Type: "bool", Default: "false"},
			want: "false",
		},
		{
			name: "empty slice default is preserved",
			doc:  FlagDoc{Type: "stringSlice", Default: "[]"},
			want: "[]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, formatDefaultValue(test.doc))
		})
	}
}

// TestFormatShorthandPrefixesShorthands verifies that present shorthands gain a
// leading dash and absent ones stay empty.
func TestFormatShorthandPrefixesShorthands(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		shorthand string
		want      string
	}{
		{
			name:      "present shorthand",
			shorthand: "i",
			want:      "-i",
		},
		{
			name:      "absent shorthand",
			shorthand: "",
			want:      "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, formatShorthand(test.shorthand))
		})
	}
}

// newTestCommandDoc builds a fully populated command document.
//
// Returns:
//   - *CommandDoc: The documented rewrite add command.
func newTestCommandDoc() *CommandDoc {
	return &CommandDoc{
		Name:        "add",
		Short:       testCommandShort,
		Long:        testCommandLong,
		Use:         testCommandUse,
		Title:       "Add",
		Description: testCommandLong,
		UseLine:     "agh-cli rewrite add [flags]",
		Examples: []ExampleDoc{
			{
				Title: "Add a rule",
				Code:  "agh-cli rewrite add example.com 192.0.2.1",
			},
		},
		Flags: []FlagDoc{
			{
				Name:      "instance",
				Shorthand: "i",
				Type:      "string",
				Usage:     "target instance name",
			},
		},
		Inherited: []FlagDoc{
			{
				Name:      "config",
				Shorthand: "c",
				Type:      "string",
				Usage:     "config path",
			},
		},
	}
}
