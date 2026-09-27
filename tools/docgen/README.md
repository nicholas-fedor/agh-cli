# docgen

CLI documentation generator for agh-cli.

## Overview

`docgen` introspects the fresh Cobra command tree from `cmd.NewRootCommand()` and emits Hugo-compatible Markdown with front matter. Generated pages are the source of truth for the site's `/cli-reference/` section.

## Usage

```bash
go run ./tools/docgen -out ./www/content/cli-reference
```

Equivalent Taskfile commands:

```bash
task docs
task docs-check
task docs-serve
```

| Flag   | Default                             | Description                    |
|--------|-------------------------------------|--------------------------------|
| `-out` | `./www/content/cli-reference`      | Markdown output directory      |

## Architecture

- `main.go` — output flag and command-tree entry point.
- `extractor.go` — Cobra command, flag, and example introspection.
- `models.go` — template-facing documentation models.
- `generator.go` — recursive output orchestration.
- `renderer.go` — Go template rendering and Hugo front matter.
- `templates/` — command and index page templates.

Generated documentation must be regenerated after command descriptions, flags, or subcommands change. `task docs-check` fails when committed documentation differs from fresh output.
