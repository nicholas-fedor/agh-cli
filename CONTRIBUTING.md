# Contributing to agh-cli

Thank you for your interest in improving agh-cli. This document describes the repository's current architecture, development workflow, and contribution requirements.

## Project overview

agh-cli is a Go 1.27.1 CLI for managing multiple AdGuard Home instances. It also publishes `pkg/adguard`, a reusable Go client for the complete AdGuard Home HTTP API.

The project is licensed under the GNU Affero General Public License v3.0 or later.

## Prerequisites

Install the following tools:

- Go 1.27.1
- [Task](https://taskfile.dev/) or GNU Make
- [golangci-lint v2](https://golangci-lint.run/)
- [Mockery v3](https://vektra.github.io/mockery/)
- [Hugo Extended](https://gohugo.io/installation/) for documentation development
- Bun for local Conventional Commit validation
- GoReleaser v2 and Cosign for release work

Run the project tool installer:

```bash
task setup
```

`task setup` downloads Go modules, installs Go-based development tools, and installs Bun dependencies from the lockfile.

To inspect optional tools:

```bash
task check-tools
```

The tool installer intentionally tracks the current upstream tool releases. Reproducibility for released binaries comes from the pinned CI actions and GoReleaser configuration, not from local `@latest` tool installs.

## Repository architecture

The dependency direction is:

```text
main.go
  -> cmd/*
    -> internal/app
      -> internal/client | internal/filtering | internal/rewrite
        -> pkg/adguard
      -> internal/config | internal/credentials | internal/instance | internal/execution
```

- `main.go` is the process entry point.
- `cmd/**` defines Cobra commands, flags, arguments, and presentation wiring.
- `internal/app` coordinates application use cases and multi-instance execution.
- `internal/client`, `internal/filtering`, and `internal/rewrite` contain domain behavior.
- `internal/config`, `internal/instance`, and `internal/execution` own configuration, catalog selection, and ordered execution.
- `internal/credentials` owns the credential store adapter, the mounted-file and environment readers, and credential resolution.
- `pkg/adguard` is the public, generated-code-independent AdGuard Home client.
- `tools/docgen` generates the Hugo CLI reference from the Cobra tree.
- `www` is the Hugo documentation module.

Do not import `pkg/adguard` from `internal` implementation details that should be exposed as domain types, and never make `pkg/adguard` depend on `internal/**` or `cmd/**`.

## Command package rules

Command packages are thin adapters. They may:

- define Cobra commands;
- register flags on the command being constructed;
- validate positional arguments;
- pass command context and output writers to the application layer;
- render prepared results.

They must not:

- read Viper directly for feature operations;
- construct `pkg/adguard` clients directly;
- implement domain algorithms;
- perform multi-instance orchestration;
- own shared package-level command or flag state.

Every command tree must be constructed fresh:

- each leaf command has an unexported constructor;
- each package exports `NewCommand()`;
- flags bind to values owned by the constructed command;
- no `init()` function registers commands or flags;
- `cmd.NewRootCommand()` returns a fresh root tree for execution and documentation.

Place a command-specific helper in the command's own file. Place helpers shared by multiple subcommands in that package's `cmd.go`. Do not create `wiring.go` or artificial `output.go` aggregation files.

## Code style

### Headers and package documentation

Every Go file starts with:

```go
// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later
```

Each package must have package documentation, preferably in `doc.go`.

### Comments

- Every exported and unexported declaration must be documented.
- Declaration comments begin with the declared identifier.
- Function comments include `Parameters:` and `Returns:` sections when applicable.
- Omit empty sections; never write `None`.
- Test function comments contain a behavioral summary only.
- Test utility functions document meaningful non-`t` parameters and actual return values.
- Comments use natural English sentences ending in periods.

### Go conventions

- Go 1.27.1 is the baseline.
- Use modern standard-library APIs such as `errors.AsType`, `errors.Join`, `slices`, `maps`, and iterator helpers where applicable.
- Use short, consistent receiver names: `c` for `Client`, `i` for `Instance`, `m` for `Manager`, `t` for `TableWriter`.
- Do not mix pointer and value receivers on one type.
- Do not use named returns.
- Wrap errors with concise lowercase context and `%w`.
- Use sentinel errors instead of dynamic inline errors where callers may match them.
- Keep imports grouped as standard library, third-party, then `github.com/nicholas-fedor/agh-cli`.

### Lint suppressions

`nolint` directives are item-scoped only. A file-wide `//nolint` is not acceptable.

Use scoped golangci-lint configuration for recurring policy. The repository currently documents these exceptions in `build/golangci-lint/golangci-lint.yaml`:

- `tagliatelle` is excluded for `pkg/adguard`, whose JSON tags mirror AdGuard's snake-case API;
- `max-public-structs` is excluded for `pkg/adguard`, whose public types mirror the OpenAPI surface;
- `goconst` ignores tests;
- revive function length is excluded for table-driven tests.

Never modify lint configuration merely to hide a new finding.

## Development commands

The Taskfile is the canonical cross-platform interface. Make targets cover the same local workflow plus release and Docker helpers.

| Action | Task | Make |
|---|---|---|
| Build | `task build` | `make build` |
| Test | `task test` | `make test` |
| Coverage | `task test-coverage` | `make test-coverage` |
| Format | `task fmt` | `make fmt` |
| Lint and autofix | `task lint` | `make lint` |
| Vet | `task vet` | `make vet` |
| Tidy modules | `task tidy` | `make tidy` |
| Generate mocks | `task mock` | `make mock` |
| Generate CLI docs | `task docs` | — |
| Verify docs drift | `task docs-check` | — |
| Serve docs | `task docs-serve` | — |
| Local checks | — | `make ci-check` |

### Lint autofix

`build/golangci-lint/golangci-lint.yaml` intentionally sets `issues.fix: true`, and both `task lint` and `make lint` apply fixes. Run them when you want autofixes.

For a read-only verification run, use the CLI override:

```bash
golangci-lint run --fix=false --config build/golangci-lint/golangci-lint.yaml ./...
```

Do not copy or modify the lint configuration for a one-off non-mutating check.

### Tests

The CI test command enables the race detector. Run the same coverage locally before submitting:

```bash
go test -race -coverprofile=coverage.out -covermode=atomic ./...
```

`make ci-check` is a fast local subset, not a complete replacement for CI.

## Testing conventions

### Package selection

- Regular unit tests are white-box tests in the package under test.
- Black-box contract and integration tests use the external `_test` package.
- Fuzz tests are white-box unless external visibility is specifically required.
- Use `t.Context()` rather than `context.Background()` in tests.
- Use `t.Parallel()` unless the test mutates process-global state such as Viper.
- Reset global configuration with `t.Cleanup`.

### `pkg/adguard` test tiers

Each library domain has three files:

```text
<domain>_test.go               package adguard
<domain>_integration_test.go  package adguard_test
<domain>_fuzz_test.go          package adguard
```

Integration tests use the concrete `adguard.Client` and `httptest.NewTestServer`. Public library contract tests must not mock the library's own interfaces.

A new domain's integration suite must cover:

- exact request contracts;
- JSON response decoding;
- optional-field preservation;
- malformed input;
- structured status errors;
- structured response errors;
- response-size limits;
- cancellation.

Fuzz targets must be bounded, offline, deterministic, and assert structured error kinds. Keep regression corpora under `pkg/**/testdata/fuzz/`; they are intentionally unignored by the repository `.gitignore`.

## Mockery

Service interfaces belong in their domain files and must remain small and feature-scoped. The concrete `*adguard.Client` satisfies each interface, and compile-time assertions must remain next to the interface.

Generate mocks with:

```bash
task mock
```

Generated files live under:

- `pkg/adguard/mocks/`
- `internal/execution/mocks/`

Never edit generated mocks manually. Regenerate them and review the diff.

Use generated mocks in consumer/application tests. Do not use them to test `pkg/adguard`'s own HTTP behavior.

## Configuration and credentials

Configuration lookup order is:

1. an explicit `--config` path;
2. the per-user configuration file;
3. `./config.yaml`.

The per-user file is `agh-cli/config.yaml` under the platform configuration root:

| Platform | Path |
|----------|------|
| Linux and other Unix | `$XDG_CONFIG_HOME/agh-cli/config.yaml`, defaulting to `~/.config/agh-cli/config.yaml` |
| macOS | `~/Library/Application Support/agh-cli/config.yaml` |
| Windows | `%AppData%\agh-cli\config.yaml` |

The first command that writes a configuration creates the per-user file in step 2, including its directory, so a fresh install never drops a configuration into whatever directory it was run from. Step 3 exists so a project can pin its own configuration.

Start from `example/config.yaml`, which documents every credential source. Never commit a real `config.yaml`, credentials, tokens, or private instance endpoints. Configuration files containing credentials must be readable only by their owner:

```bash
chmod 600 config.yaml
```

If a credential is ever committed or exposed, remove it and rotate it immediately with `agh-cli instance credentials set <name>`.

### Credential model

- The operating system credential store is the default store: the macOS Keychain, the Linux and BSD Secret Service, or the Windows Credential Manager. It is reached through `internal/credentials` behind the project-owned `Store` interface, so no `pkg/adguard`, `internal/app`, or `cmd` code may name a go-keyring error or its platform behavior.
- `credentials.service` in the configuration file is the store namespace, defaulting to `agh-cli`. A credential key is the `--key` value of `set`, then the configured `credential.key`, then the instance name. Keys never embed a host.
- Supported `credential.source` values are `keyring`, `file`, `env`, `plaintext`, and `none`. A configured source is the only source that is read, so an unreadable credential is an error rather than a fallback.
- `file` and `env` sources are owned by Docker, Kubernetes, systemd, Vault, or the operator. `clear` refuses them, and no change to those instances may be made from the CLI.
- A secret must never reach an error, a status value, a log line, a test fixture, or documentation. Errors may carry the service, the key, the file path, or the variable name.
- `agh-cli instance credentials` deliberately has no `get` subcommand, and `agh-cli instance add --password` is deprecated. Do not reintroduce a command that prints a secret or a flag that takes one as an argument.

### Documentation duties for a credential change

A user-visible credential change must update, in the same change:

- `README.md`, including the credential workflow and the source table;
- `www/content/_index.md` and `www/content/getting-started/_index.md`;
- `example/config.yaml`, when a field or source changes;
- the generated `www/content/cli-reference/` output via `task docs`.

## Documentation

The CLI reference is generated from the Cobra tree:

```bash
task docs
task docs-check
task docs-serve
```

- `task docs` regenerates `www/content/cli-reference/`.
- `task docs-check` fails when committed output is stale.
- `task docs-serve` requires Hugo Extended and may download the hextra module on first use.
- Do not commit Hugo's `public/` output or `.hugo_build.lock`.

When a command's `Use`, `Short`, `Long`, `Example`, flags, or subcommands change, regenerate and commit the CLI reference.

## Commit messages and changelog

Commit messages follow Conventional Commits, enforced by Commitlint:

```text
feat(clients): add client search
fix(config): tighten config permissions
docs(readme): clarify install flow
```

The changelog is generated from commit history by git-cliff. Do not edit `CHANGELOG.md` manually.

Use imperative, present-tense subjects and keep scopes focused.

## Pull request expectations

Before opening a pull request:

1. Keep the diff focused on one logical concern.
2. Add or update tests for behavior changes.
3. Run autofix lint, tests with the race detector, vet, and static analysis.
4. Regenerate mocks when interfaces change.
5. Run `task docs-check` when commands change.
6. Update README and documentation site content when user-facing behavior changes.
7. Do not include generated build output, local configuration, or credentials.

## Release overview

Stable releases are triggered by tags matching `vX.Y.Z`. Nightly image builds run from `main`.

Maintainers must use GoReleaser through CI rather than publishing locally. Release automation requires:

- GitHub Actions environment `CI` with the required secrets;
- GoReleaser v2;
- Cosign keyless signing;
- Docker Hub and GHCR credentials for image publication.

Use the stable workflow's `dry_run` input to produce a snapshot without publishing.

## License

By contributing, you agree that your contributions are licensed under the GNU Affero General Public License v3.0 or later.
