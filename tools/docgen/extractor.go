// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// DocExtractor defines the interface for extracting documentation from Cobra
// commands.
type DocExtractor interface {
	// Extract builds a CommandDoc from a command and its parent path.
	//
	// Parameters:
	//   - command: The command to document.
	//   - parentPath: The full path of the parent command.
	//
	// Returns:
	//   - *CommandDoc: The extracted documentation data.
	Extract(command *cobra.Command, parentPath string) *CommandDoc
}

// cobraExtractor implements DocExtractor using Cobra command metadata.
type cobraExtractor struct{}

const (
	// Maximum length of a command description before truncation.
	maxDescriptionLen = 160

	// Suffix marking a truncated command description.
	ellipsisSuffix = "..."

	// Byte length of [ellipsisSuffix].
	ellipsisLen = len(ellipsisSuffix)

	// Display title of the generated reference index.
	indexTitle = "CLI Reference"

	// Description format of the generated reference index.
	indexDescriptionFormat = "Complete command reference for %s, organized by functional area."
)

// newCobraExtractor creates a documentation extractor for Cobra commands.
//
// Returns:
//   - *cobraExtractor: A new extractor for Cobra commands.
func newCobraExtractor() *cobraExtractor {
	return &cobraExtractor{}
}

// Extract builds a CommandDoc from a command and its parent path.
//
// Parameters:
//   - command: The Cobra command to extract documentation from.
//   - parentPath: The full path of the parent command.
//
// Returns:
//   - *CommandDoc: The extracted documentation data.
func (e *cobraExtractor) Extract(command *cobra.Command, parentPath string) *CommandDoc {
	fullPath := buildFullPath(command, parentPath)
	description := command.Long
	if description == "" {
		description = command.Short
	}

	doc := &CommandDoc{
		Name:        command.Name(),
		Short:       command.Short,
		Long:        command.Long,
		Use:         command.Use,
		Example:     command.Example,
		UseLine:     buildUseLine(command.Use, fullPath),
		Title:       buildTitle(command),
		Description: buildDescription(description),
		FullPath:    fullPath,
		Examples:    parseExamples(command.Example, fullPath, command.Use),
		Flags:       buildLocalFlags(command),
		Inherited:   buildInheritedFlags(command),
		SubCommands: e.buildSubCommands(command, fullPath),
	}

	if command.HasAvailableSubCommands() {
		doc.HasSubs = true
		doc.Index = buildIndex(command)
	}

	return doc
}

// buildSubCommands documents the published subcommands of a command.
//
// Parameters:
//   - command: The command owning the subcommands.
//   - parentPath: The full path of the documented command.
//
// Returns:
//   - []*CommandDoc: The documented subcommands in Cobra order.
func (e *cobraExtractor) buildSubCommands(
	command *cobra.Command,
	parentPath string,
) []*CommandDoc {
	var docs []*CommandDoc

	for _, child := range command.Commands() {
		if !isDocumentedCommand(child) {
			continue
		}

		docs = append(docs, e.Extract(child, parentPath))
	}

	return docs
}

// buildDescription creates a truncated description from a long description.
//
// Parameters:
//   - long: The full long description text.
//
// Returns:
//   - string: The description, truncated to [maxDescriptionLen] if necessary.
func buildDescription(long string) string {
	description := strings.ReplaceAll(long, "\n", " ")

	description = strings.TrimSpace(description)

	if len(description) > maxDescriptionLen {
		description = description[:maxDescriptionLen-ellipsisLen] + ellipsisSuffix
	}

	return description
}

// buildFlags extracts documentation from a flag set.
//
// Parameters:
//   - flags: The flag set to extract documentation from.
//
// Returns:
//   - []FlagDoc: A list of flag documentation entries.
func buildFlags(flags *pflag.FlagSet) []FlagDoc {
	var docs []FlagDoc

	flags.VisitAll(func(entry *pflag.Flag) {
		docs = append(docs, FlagDoc{
			Name:      entry.Name,
			Shorthand: entry.Shorthand,
			Default:   entry.DefValue,
			Type:      entry.Value.Type(),
			Usage:     entry.Usage,
		})
	})

	return docs
}

// buildFullPath constructs the full command path from a parent path and command
// name.
//
// Parameters:
//   - command: The Cobra command.
//   - parentPath: The parent command path.
//
// Returns:
//   - string: The full command path, such as "agh-cli rewrite add".
func buildFullPath(command *cobra.Command, parentPath string) string {
	if command.Name() == parentPath {
		return parentPath
	}

	return parentPath + " " + command.Name()
}

// buildIndex constructs the index documentation for a command group.
//
// Parameters:
//   - command: The parent Cobra command with subcommands.
//
// Returns:
//   - *IndexDoc: The index documentation with sections and entries.
func buildIndex(command *cobra.Command) *IndexDoc {
	index := &IndexDoc{
		Title:       indexTitle,
		Description: fmt.Sprintf(indexDescriptionFormat, command.Root().Name()),
	}

	for _, child := range command.Commands() {
		if !isDocumentedCommand(child) {
			continue
		}

		index.Sections = append(index.Sections, buildSection(child))
	}

	return index
}

// buildInheritedFlags documents the flags a command inherits from its parents.
//
// Parameters:
//   - command: The Cobra command to inspect.
//
// Returns:
//   - []FlagDoc: The inherited flags, or nil when there are none.
func buildInheritedFlags(command *cobra.Command) []FlagDoc {
	if !command.HasAvailableInheritedFlags() {
		return nil
	}

	return buildFlags(command.InheritedFlags())
}

// buildLocalFlags documents the flags declared on a command.
//
// Parameters:
//   - command: The Cobra command to inspect.
//
// Returns:
//   - []FlagDoc: The declared flags, or nil when there are none.
func buildLocalFlags(command *cobra.Command) []FlagDoc {
	if !command.HasAvailableFlags() {
		return nil
	}

	return buildFlags(command.Flags())
}

// buildSection constructs one index section for a top-level command.
//
// Parameters:
//   - child: The child command documented by the section.
//
// Returns:
//   - sectionEntry: The section with its subcommand entries.
func buildSection(child *cobra.Command) sectionEntry {
	section := sectionEntry{
		Name:        child.Name(),
		Description: firstParagraph(child.Long),
		HasSubs:     child.HasAvailableSubCommands(),
	}

	if section.HasSubs {
		section.Title = child.Short
	} else {
		section.Title = titleCase(child.Name())
	}

	section.SubCommands = buildSectionEntries(child)

	return section
}

// buildSectionEntries builds the index entries linking to a command's pages.
//
// Command groups link to every documented subcommand, while leaf commands link
// to their own section page.
//
// Parameters:
//   - child: The child command owning the entries.
//
// Returns:
//   - []subCommandEntry: The entries of the section.
func buildSectionEntries(child *cobra.Command) []subCommandEntry {
	if !child.HasAvailableSubCommands() {
		return []subCommandEntry{
			{
				Name:        child.Name(),
				Description: child.Short,
				URL:         fmt.Sprintf("/cli-reference/%s/", child.Name()),
			},
		}
	}

	entries := make([]subCommandEntry, 0, len(child.Commands()))

	for _, sub := range child.Commands() {
		if !isDocumentedCommand(sub) {
			continue
		}

		entries = append(entries, subCommandEntry{
			Name:        sub.Name(),
			Description: sub.Short,
			URL:         fmt.Sprintf("/cli-reference/%s/%s/", child.Name(), sub.Name()),
		})
	}

	return entries
}

// buildTitle generates a display title for a command.
//
// Command groups use their short description, while leaf commands use their
// title-cased name.
//
// Parameters:
//   - command: The Cobra command.
//
// Returns:
//   - string: The title-cased command name or the group short description.
func buildTitle(command *cobra.Command) string {
	if !command.HasAvailableSubCommands() {
		return titleCase(command.Name())
	}

	return command.Short
}

// buildUseLine constructs the usage line from a Use field and a full path.
//
// Parameters:
//   - use: The Use field from the Cobra command.
//   - fullPath: The full command path.
//
// Returns:
//   - string: The formatted usage line.
func buildUseLine(use, fullPath string) string {
	if use == "" {
		return ""
	}

	return usageCode(fullPath, use)
}

// firstParagraph extracts the first paragraph from a multi-paragraph text.
//
// Parameters:
//   - text: The full text to extract from.
//
// Returns:
//   - string: The first paragraph with newlines replaced by spaces.
func firstParagraph(text string) string {
	text = strings.TrimSpace(text)
	if idx := strings.Index(text, "\n\n"); idx != -1 {
		text = text[:idx]
	}

	return strings.ReplaceAll(text, "\n", " ")
}

// isDocumentedCommand reports whether a command belongs in the documentation.
//
// Hidden, deprecated, and additional help topic commands are not published.
//
// Parameters:
//   - command: The Cobra command to inspect.
//
// Returns:
//   - bool: True when the command is available and not a help topic.
func isDocumentedCommand(command *cobra.Command) bool {
	return command.IsAvailableCommand() && !command.IsAdditionalHelpTopicCommand()
}

// parseExampleBlock parses one blank-line separated example block.
//
// A leading comment line supplies the example title, and every remaining line
// supplies the example code.
//
// Parameters:
//   - block: The raw example block.
//
// Returns:
//   - ExampleDoc: The parsed example documentation.
//   - bool: False when the block holds no example code.
func parseExampleBlock(block string) (ExampleDoc, bool) {
	var (
		comment   string
		codeLines []string
	)

	for line := range strings.SplitSeq(block, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "#") {
			comment = trimmed
		} else if trimmed != "" {
			codeLines = append(codeLines, strings.TrimLeft(line, " "))
		}
	}

	if len(codeLines) == 0 {
		return ExampleDoc{}, false
	}

	title := strings.TrimSpace(strings.TrimPrefix(comment, "#"))

	return ExampleDoc{
		Title: title,
		Code:  strings.TrimSpace(strings.Join(codeLines, "\n")),
	}, true
}

// parseExamples parses example text into structured example documentation.
//
// A single example that only repeats the usage line is suppressed because the
// usage section already documents it.
//
// Parameters:
//   - raw: The raw example text from the Cobra command.
//   - fullPath: The full command path for context.
//   - use: The Use field from the Cobra command.
//
// Returns:
//   - []ExampleDoc: A list of parsed example documentation entries.
func parseExamples(raw, fullPath, use string) []ExampleDoc {
	var examples []ExampleDoc

	for block := range strings.SplitSeq(strings.TrimSpace(raw), "\n\n") {
		example, ok := parseExampleBlock(block)
		if !ok {
			continue
		}

		examples = append(examples, example)
	}

	if len(examples) == 1 && examples[0].Code == usageCode(fullPath, use) {
		return nil
	}

	return examples
}

// titleCase upper-cases the first letter of every space-separated word.
//
// Parameters:
//   - value: The text to convert.
//
// Returns:
//   - string: The title-cased text.
func titleCase(value string) string {
	words := strings.Split(value, " ")

	for index, word := range words {
		if word == "" {
			continue
		}

		first, size := utf8.DecodeRuneInString(word)

		words[index] = string(unicode.ToUpper(first)) + word[size:]
	}

	return strings.Join(words, " ")
}

// usageCode combines a full command path with its declared arguments.
//
// Parameters:
//   - fullPath: The full command path.
//   - use: The Use field from the Cobra command.
//
// Returns:
//   - string: The usage line of the command.
func usageCode(fullPath, use string) string {
	args := useArguments(use)
	if args == "" {
		return fullPath
	}

	return fullPath + " " + args
}

// useArguments returns the arguments declared after the command name.
//
// Parameters:
//   - use: The Use field from the Cobra command.
//
// Returns:
//   - string: The trimmed arguments, or an empty string when the command takes
//     no arguments.
func useArguments(use string) string {
	name, _, _ := strings.Cut(use, " ")

	return strings.TrimSpace(strings.TrimPrefix(use, name))
}
