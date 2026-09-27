// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"text/template"
)

// TemplateRenderer defines the interface for rendering documentation templates.
type TemplateRenderer interface {
	// RenderCommand renders a command documentation page to a file.
	//
	// Parameters:
	//   - doc: The command documentation to render.
	//   - filePath: The output file path.
	//
	// Returns:
	//   - error: Non-nil if template execution or the file write fails.
	RenderCommand(doc *CommandDoc, filePath string) error

	// RenderIndex renders an index documentation page to a file.
	//
	// Parameters:
	//   - doc: The index documentation to render.
	//   - filePath: The output file path.
	//
	// Returns:
	//   - error: Non-nil if template execution or the file write fails.
	RenderIndex(doc *IndexDoc, filePath string) error
}

// hugoRenderer implements TemplateRenderer for Hugo-compatible Markdown.
type hugoRenderer struct {
	// commandTmpl is the template for command documentation pages.
	commandTmpl *template.Template
	// indexTmpl is the template for index documentation pages.
	indexTmpl *template.Template
}

const (
	// Permission mode for created directories.
	dirPerms = 0o755

	// Permission mode for created files.
	filePerms = 0o600

	// File name of the command page template.
	commandTemplateName = "command.tmpl"

	// File name of the index page template.
	indexTemplateName = "index.tmpl"

	// Directory holding the page templates.
	templateDirName = "templates"
)

// newHugoRenderer creates a new hugoRenderer with loaded templates.
//
// Returns:
//   - *hugoRenderer: A new renderer for Hugo-compatible Markdown.
//   - error: Non-nil if template parsing fails.
func newHugoRenderer() (*hugoRenderer, error) {
	funcMap := template.FuncMap{
		"shorthand":  formatShorthand,
		"defaultVal": formatDefaultValue,
	}

	templateDir := filepath.Join(filepath.Dir(callerFile()), templateDirName)

	commandTmpl, err := template.New(commandTemplateName).
		Funcs(funcMap).
		ParseFiles(filepath.Join(templateDir, commandTemplateName))
	if err != nil {
		return nil, fmt.Errorf("parse command template: %w", err)
	}

	indexTmpl, err := template.New(indexTemplateName).
		Funcs(funcMap).
		ParseFiles(filepath.Join(templateDir, indexTemplateName))
	if err != nil {
		return nil, fmt.Errorf("parse index template: %w", err)
	}

	return &hugoRenderer{
		commandTmpl: commandTmpl,
		indexTmpl:   indexTmpl,
	}, nil
}

// callerFile returns the source file path of the caller using [runtime.Caller].
//
// Returns:
//   - string: The caller's source file path, or an empty string when it cannot
//     be determined.
func callerFile() string {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		return ""
	}

	return filename
}

// RenderCommand renders a command documentation page to a file.
//
// Parameters:
//   - doc: The command documentation to render.
//   - filePath: The output file path.
//
// Returns:
//   - error: Non-nil if template execution or the file write fails.
func (r *hugoRenderer) RenderCommand(doc *CommandDoc, filePath string) error {
	err := renderTemplate(r.commandTmpl, doc, filePath)
	if err != nil {
		return fmt.Errorf("render command page: %w", err)
	}

	return nil
}

// RenderIndex renders an index documentation page to a file.
//
// Parameters:
//   - doc: The index documentation to render.
//   - filePath: The output file path.
//
// Returns:
//   - error: Non-nil if template execution or the file write fails.
func (r *hugoRenderer) RenderIndex(doc *IndexDoc, filePath string) error {
	err := renderTemplate(r.indexTmpl, doc, filePath)
	if err != nil {
		return fmt.Errorf("render index page: %w", err)
	}

	return nil
}

// formatDefaultValue renders a flag default value for a Markdown table.
//
// Parameters:
//   - doc: The flag documentation holding the default value and type.
//
// Returns:
//   - string: The quoted empty string default, or the raw default value.
func formatDefaultValue(doc FlagDoc) string {
	if doc.Type == "string" && doc.Default == "" {
		return `""`
	}

	return doc.Default
}

// formatShorthand renders a flag shorthand for a Markdown table.
//
// Parameters:
//   - shorthand: The single-character shorthand, which may be empty.
//
// Returns:
//   - string: The dash-prefixed shorthand, or an empty string.
func formatShorthand(shorthand string) string {
	if shorthand == "" {
		return ""
	}

	return "-" + shorthand
}

// renderTemplate executes a template with data and writes the result to a file.
//
// Parameters:
//   - tmpl: The template to execute.
//   - data: The data to pass to the template.
//   - filePath: The output file path.
//
// Returns:
//   - error: Non-nil if template execution or the file write fails.
func renderTemplate(tmpl *template.Template, data any, filePath string) error {
	var buf bytes.Buffer

	err := tmpl.Execute(&buf, data)
	if err != nil {
		return fmt.Errorf("execute template for %s: %w", filePath, err)
	}

	err = os.WriteFile(filePath, buf.Bytes(), filePerms)
	if err != nil {
		return fmt.Errorf("write file %s: %w", filePath, err)
	}

	return nil
}
