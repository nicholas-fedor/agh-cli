// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	// Root command name used by extractor tests.
	testRootName = "agh-cli"

	// Root short description used by extractor tests.
	testRootShort = "CLI for managing multiple AdGuard Home instances"

	// Root long description used by extractor tests.
	testRootLong = "A Go CLI that provides CRUD operations for interacting with " +
		"multiple AdGuard Home instances simultaneously."

	// Short description of the documented leaf command.
	testCommandShort = "Add a DNS rewrite rule"

	// Long description of the documented leaf command.
	testCommandLong = "Add a DNS rewrite rule to the selected instances."

	// Use field of the documented leaf command.
	testCommandUse = "add [flags]"

	// Example field of the documented leaf command.
	testCommandExample = "  # Add a rule for example.com\n" +
		"  agh-cli rewrite add example.com 192.0.2.1"

	// Short description of the documented command group.
	testGroupShort = "DNS rewrite operations"

	// Description exceeding [maxDescriptionLen] and therefore truncating.
	longDescription = "This is a very long description that should be truncated because it exceeds the " +
		"maximum allowed length of one hundred and sixty characters for documentation purposes"
)

// TestNewCobraExtractorCreatesExtractor verifies that the constructor returns a
// usable extractor.
func TestNewCobraExtractorCreatesExtractor(t *testing.T) {
	t.Parallel()

	extractor := newCobraExtractor()

	require.NotNil(t, extractor)
}

// TestCobraExtractorExtractDocumentsLeafCommand verifies that a leaf command
// yields its published descriptions, usage line, and examples.
func TestCobraExtractorExtractDocumentsLeafCommand(t *testing.T) {
	t.Parallel()

	extractor := newCobraExtractor()
	command := newTestLeafCommand()

	doc := extractor.Extract(command, "agh-cli rewrite")

	require.NotNil(t, doc)
	assert.Equal(t, "add", doc.Name)
	assert.Equal(t, testCommandShort, doc.Short)
	assert.Equal(t, testCommandLong, doc.Long)
	assert.Equal(t, testCommandUse, doc.Use)
	assert.Equal(t, "agh-cli rewrite add", doc.FullPath)
	assert.Equal(t, "Add", doc.Title)
	assert.Equal(t, testCommandLong, doc.Description)
	assert.Equal(t, "agh-cli rewrite add [flags]", doc.UseLine)
	assert.False(t, doc.HasSubs)
	assert.Nil(t, doc.Index)
	assert.Empty(t, doc.SubCommands)

	require.Len(t, doc.Examples, 1)
	assert.Equal(t, "Add a rule for example.com", doc.Examples[0].Title)
	assert.Equal(t, "agh-cli rewrite add example.com 192.0.2.1", doc.Examples[0].Code)
}

// TestCobraExtractorExtractFallsBackToShortDescription verifies that commands
// without a long description still receive front-matter content.
func TestCobraExtractorExtractFallsBackToShortDescription(t *testing.T) {
	t.Parallel()

	extractor := newCobraExtractor()
	command := &cobra.Command{
		Use:   "version",
		Short: "Print the application version",
	}

	doc := extractor.Extract(command, testRootName)

	require.NotNil(t, doc)
	assert.Equal(t, "Print the application version", doc.Description)
}

// TestCobraExtractorExtractWalksVisibleSubcommands verifies that available
// subcommands are documented with their full path while hidden commands are
// skipped.
func TestCobraExtractorExtractWalksVisibleSubcommands(t *testing.T) {
	t.Parallel()

	extractor := newCobraExtractor()
	command := newTestGroupCommand()
	command.AddCommand(&cobra.Command{
		Use:    "secret",
		Short:  "Hidden command",
		Hidden: true,
		Run:    func(_ *cobra.Command, _ []string) {},
	})

	doc := extractor.Extract(command, testRootName)

	require.NotNil(t, doc)
	assert.True(t, doc.HasSubs)
	require.NotNil(t, doc.Index)
	require.Len(t, doc.SubCommands, 1)
	assert.Equal(t, "add", doc.SubCommands[0].Name)
	assert.Equal(t, "agh-cli rewrite add", doc.SubCommands[0].FullPath)
}

// TestCobraExtractorExtractCollectsFlags verifies that local and inherited
// flags are documented separately.
func TestCobraExtractorExtractCollectsFlags(t *testing.T) {
	t.Parallel()

	extractor := newCobraExtractor()

	command := newTestRunnableCommand("list", "List rules")
	command.Flags().StringP("instance", "i", "", "target instance name")

	parent := newTestRootCommand()
	parent.PersistentFlags().StringP("config", "c", "", "config path")
	parent.AddCommand(command)

	doc := extractor.Extract(command, parent.Name())

	require.NotNil(t, doc)
	require.Len(t, doc.Flags, 1)
	assert.Equal(t, "instance", doc.Flags[0].Name)
	assert.Equal(t, "i", doc.Flags[0].Shorthand)
	assert.Equal(t, "string", doc.Flags[0].Type)
	assert.Empty(t, doc.Flags[0].Default)
	assert.Equal(t, "target instance name", doc.Flags[0].Usage)

	require.Len(t, doc.Inherited, 1)
	assert.Equal(t, "config", doc.Inherited[0].Name)
	assert.Equal(t, "c", doc.Inherited[0].Shorthand)
	assert.Equal(t, "string", doc.Inherited[0].Type)
	assert.Empty(t, doc.Inherited[0].Default)
	assert.Equal(t, "config path", doc.Inherited[0].Usage)
}

// TestBuildDescriptionTruncatesLongText verifies that descriptions collapse
// newlines and are truncated at the documented limit.
func TestBuildDescriptionTruncatesLongText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		long string
		want string
	}{
		{
			name: "short description is preserved",
			long: "Short description",
			want: "Short description",
		},
		{
			name: "newlines collapse into spaces",
			long: "First line\nsecond line",
			want: "First line second line",
		},
		{
			name: "long description truncates",
			long: longDescription,
			want: "This is a very long description that should be truncated because it exceeds the " +
				"maximum allowed length of one hundred and sixty characters for documentation ...",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, buildDescription(test.long))
		})
	}
}

// TestBuildFlagsDocumentsEveryFlag verifies that flag metadata is copied into
// the rendered documentation model.
func TestBuildFlagsDocumentsEveryFlag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		flags func() *pflag.FlagSet
		want  []FlagDoc
	}{
		{
			name:  "empty flag set",
			flags: func() *pflag.FlagSet { return pflag.NewFlagSet("test", pflag.ContinueOnError) },
			want:  nil,
		},
		{
			name: "string flag with shorthand",
			flags: func() *pflag.FlagSet {
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flags.StringP("instance", "i", "", "target instance name")

				return flags
			},
			want: []FlagDoc{
				{
					Name:      "instance",
					Shorthand: "i",
					Default:   "",
					Type:      "string",
					Usage:     "target instance name",
				},
			},
		},
		{
			name: "boolean flag with default",
			flags: func() *pflag.FlagSet {
				flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
				flags.Bool("all", true, "target all instances")

				return flags
			},
			want: []FlagDoc{
				{
					Name:      "all",
					Shorthand: "",
					Default:   "true",
					Type:      "bool",
					Usage:     "target all instances",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, buildFlags(test.flags()))
		})
	}
}

// TestBuildFullPathJoinsParentAndName verifies that the root command keeps its
// own name while subcommands extend the parent path.
func TestBuildFullPathJoinsParentAndName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		command    *cobra.Command
		parentPath string
		want       string
	}{
		{
			name:       "root command matches its parent path",
			command:    &cobra.Command{Use: testRootName},
			parentPath: testRootName,
			want:       testRootName,
		},
		{
			name:       "subcommand extends the parent path",
			command:    &cobra.Command{Use: "rewrite"},
			parentPath: testRootName,
			want:       "agh-cli rewrite",
		},
		{
			name:       "command name ignores use arguments",
			command:    &cobra.Command{Use: "add [flags]"},
			parentPath: "agh-cli rewrite",
			want:       "agh-cli rewrite add",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, buildFullPath(test.command, test.parentPath))
		})
	}
}

// TestBuildIndexDocumentsTopLevelCommands verifies that the index names the
// project, groups command sections, and links leaf commands to their own page.
func TestBuildIndexDocumentsTopLevelCommands(t *testing.T) {
	t.Parallel()

	root := newTestRootCommand()
	root.AddCommand(newTestGroupCommand())
	root.AddCommand(newTestRunnableCommand("version", "Print the application version"))

	index := buildIndex(root)

	require.NotNil(t, index)
	assert.Equal(t, indexTitle, index.Title)
	assert.Equal(
		t,
		"Complete command reference for agh-cli, organized by functional area.",
		index.Description,
	)
	require.Len(t, index.Sections, 2)

	group := index.Sections[0]
	assert.Equal(t, "rewrite", group.Name)
	assert.Equal(t, testGroupShort, group.Title)
	assert.True(t, group.HasSubs)
	require.Len(t, group.SubCommands, 1)
	assert.Equal(t, "add", group.SubCommands[0].Name)
	assert.Equal(t, testCommandShort, group.SubCommands[0].Description)
	assert.Equal(t, "/cli-reference/rewrite/add/", group.SubCommands[0].URL)

	leaf := index.Sections[1]
	assert.Equal(t, "version", leaf.Name)
	assert.Equal(t, "Version", leaf.Title)
	assert.False(t, leaf.HasSubs)
	require.Len(t, leaf.SubCommands, 1)
	assert.Equal(t, "version", leaf.SubCommands[0].Name)
	assert.Equal(t, "Print the application version", leaf.SubCommands[0].Description)
	assert.Equal(t, "/cli-reference/version/", leaf.SubCommands[0].URL)
}

// TestBuildIndexSkipsUnavailableCommands verifies that hidden commands are
// excluded from the generated index.
func TestBuildIndexSkipsUnavailableCommands(t *testing.T) {
	t.Parallel()

	root := newTestRootCommand()
	root.AddCommand(&cobra.Command{Use: "secret", Hidden: true})

	index := buildIndex(root)

	require.NotNil(t, index)
	assert.Empty(t, index.Sections)
}

// TestBuildTitlePrefersShortForGroups verifies that command groups are titled
// with their short description and leaves with their name.
func TestBuildTitlePrefersShortForGroups(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command func() *cobra.Command
		want    string
	}{
		{
			name:    "leaf command uses its name",
			command: func() *cobra.Command { return &cobra.Command{Use: "add"} },
			want:    "Add",
		},
		{
			name: "command group uses its short description",
			command: func() *cobra.Command {
				group := &cobra.Command{Use: "rewrite", Short: testGroupShort}
				group.AddCommand(newTestRunnableCommand("add", testCommandShort))

				return group
			},
			want: testGroupShort,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, buildTitle(test.command()))
		})
	}
}

// TestBuildUseLineCombinesPathAndArguments verifies that the usage line keeps
// the command arguments that follow the command name.
func TestBuildUseLineCombinesPathAndArguments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		use      string
		fullPath string
		want     string
	}{
		{
			name:     "empty use has no usage line",
			use:      "",
			fullPath: "agh-cli",
			want:     "",
		},
		{
			name:     "use without arguments uses the full path",
			use:      "add",
			fullPath: "agh-cli rewrite add",
			want:     "agh-cli rewrite add",
		},
		{
			name:     "use with arguments appends the arguments",
			use:      "add [flags]",
			fullPath: "agh-cli rewrite add",
			want:     "agh-cli rewrite add [flags]",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, buildUseLine(test.use, test.fullPath))
		})
	}
}

// TestFirstParagraphKeepsLeadingText verifies that only the first paragraph is
// returned with its newlines flattened.
func TestFirstParagraphKeepsLeadingText(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		text string
		want string
	}{
		{
			name: "single paragraph",
			text: "First paragraph",
			want: "First paragraph",
		},
		{
			name: "multiple paragraphs",
			text: "First paragraph\n\nSecond paragraph",
			want: "First paragraph",
		},
		{
			name: "wrapped paragraph",
			text: "Line one\nLine two",
			want: "Line one Line two",
		},
		{
			name: "empty text",
			text: "   ",
			want: "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, firstParagraph(test.text))
		})
	}
}

// TestParseExamplesSplitsCommentedBlocks verifies that example text becomes
// titled blocks and that a usage-only block is suppressed.
func TestParseExamplesSplitsCommentedBlocks(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		raw  string
		use  string
		want []ExampleDoc
	}{
		{
			name: "titled example",
			raw:  "  # Add a rule\n  agh-cli rewrite add example.com 192.0.2.1",
			use:  "add [flags]",
			want: []ExampleDoc{
				{Title: "Add a rule", Code: "agh-cli rewrite add example.com 192.0.2.1"},
			},
		},
		{
			name: "multiple examples",
			raw:  "# First\nagh-cli rewrite list\n\n# Second\nagh-cli rewrite diff",
			use:  "list",
			want: []ExampleDoc{
				{Title: "First", Code: "agh-cli rewrite list"},
				{Title: "Second", Code: "agh-cli rewrite diff"},
			},
		},
		{
			name: "comment without code is skipped",
			raw:  "# Only a comment\n\n# Real\nagh-cli rewrite list",
			use:  "list",
			want: []ExampleDoc{
				{Title: "Real", Code: "agh-cli rewrite list"},
			},
		},
		{
			name: "usage line duplicate is suppressed",
			raw:  "agh-cli rewrite add [flags]",
			use:  "add [flags]",
			want: nil,
		},
		{
			name: "no examples",
			raw:  "   ",
			use:  "add [flags]",
			want: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := parseExamples(test.raw, "agh-cli rewrite add", test.use)

			assert.Equal(t, test.want, got)
		})
	}
}

// TestTitleCaseCapitalizesEachWord verifies that every space-separated word
// receives an initial capital without altering the remaining characters.
func TestTitleCaseCapitalizesEachWord(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value string
		want  string
	}{
		{
			name:  "lowercase word",
			value: "add",
			want:  "Add",
		},
		{
			name:  "already capitalized word",
			value: "Add",
			want:  "Add",
		},
		{
			name:  "multiple words",
			value: "my command",
			want:  "My Command",
		},
		{
			name:  "multibyte word",
			value: "ünicode",
			want:  "Ünicode",
		},
		{
			name:  "empty value",
			value: "",
			want:  "",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, test.want, titleCase(test.value))
		})
	}
}

// newTestRootCommand builds a root command with the published identity.
//
// Returns:
//   - *cobra.Command: The root command used by extractor tests.
func newTestRootCommand() *cobra.Command {
	return &cobra.Command{
		Use:   testRootName,
		Short: testRootShort,
		Long:  testRootLong,
	}
}

// newTestGroupCommand builds a command group owning one leaf command.
//
// Returns:
//   - *cobra.Command: The rewrite command group.
func newTestGroupCommand() *cobra.Command {
	group := &cobra.Command{
		Use:   "rewrite",
		Short: testGroupShort,
		Long:  "Manage DNS rewrite rules.\n\nAdditional detail is omitted from the index.",
	}

	group.AddCommand(newTestLeafCommand())

	return group
}

// newTestLeafCommand builds the documented leaf command.
//
// Returns:
//   - *cobra.Command: The rewrite add command.
func newTestLeafCommand() *cobra.Command {
	return &cobra.Command{
		Use:     testCommandUse,
		Short:   testCommandShort,
		Long:    testCommandLong,
		Example: testCommandExample,
		Run:     func(_ *cobra.Command, _ []string) {},
	}
}

// newTestRunnableCommand builds a runnable leaf command without subcommands.
//
// Parameters:
//   - use: Published invocation syntax of the command.
//   - short: Published one-line description of the command.
//
// Returns:
//   - *cobra.Command: The runnable leaf command.
func newTestRunnableCommand(use, short string) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Run:   func(_ *cobra.Command, _ []string) {},
	}
}
