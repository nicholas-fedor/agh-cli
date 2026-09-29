# Agent Instructions

These instructions apply to automated contributors working in this repository.

## Repository facts

- Module: `github.com/nicholas-fedor/agh-cli`
- Go directive: `1.27.1`
- Public library: `pkg/adguard`
- CLI entry point: `main.go`
- Canonical command tree: `cmd.NewRootCommand()`
- Canonical local task interface: `Taskfile.yml`
- Canonical lint configuration: `build/golangci-lint/golangci-lint.yaml`
- Canonical Mockery configuration: `build/mockery/mockery.yaml`
- Generated CLI docs: `www/content/cli-reference/`
- Default credential store service: `agh-cli`

## Non-negotiable rules

- Do not use `rtk`; it is not installed on the development host.
- Do not run destructive or state-changing Git commands unless the user explicitly authorizes them.
- Never commit, push, reset, checkout, stash, or clean without explicit authorization.
- Preserve all pre-existing uncommitted work. Inspect overlapping files before editing.
- Never hand-edit generated Go code, generated Mockery files, or Hugo `public/` output.
- Never change `issues.fix` away from `true` in the golangci-lint configuration. Autofix is intentional.
- For a one-off non-mutating lint check, use the CLI flag `--fix=false`; do not copy or modify the configuration.
- Do not add file-wide `//nolint` directives. Suppressions are item-scoped, specific, and require a concrete reason.
- Do not weaken lint policy merely to silence a finding.
- Do not commit credentials, real `config.yaml` files, tokens, or private endpoints.

## Architecture

The intended dependency direction is:

```text
main.go
  -> cmd
    -> internal/app
      -> internal/client | internal/filtering | internal/rewrite
        -> pkg/adguard
      -> internal/config | internal/credentials | internal/instance | internal/execution
```

- `cmd` contains Cobra definitions, flags, argument validation, and presentation wiring only.
- `internal/app` is the glue between commands, domain packages, `pkg/adguard`, instance selection, and execution.
- Domain packages own use cases, validation, request shaping, wildcard behavior, and result shaping.
- `pkg/adguard` owns transport, auth, timeouts, bounded responses, strict decoding, typed errors, and public domain types.
- `internal/config` owns local YAML persistence.
- `internal/credentials` owns the credential store adapter, the mounted-secret and environment readers, and credential resolution.
- `internal/instance` owns validated instance configuration and catalog selection.
- `internal/execution` owns ordered multi-target execution, cancellation, outcomes, and error aggregation.

Do not let `cmd` import `pkg/adguard` for feature operations. Route feature behavior through `internal/app` and its domain package.

## Command construction

Every command tree must be constructed fresh:

- `cmd.NewRootCommand()` returns a new root tree.
- Each feature package exports `NewCommand()`.
- Each leaf command has an unexported constructor.
- Flags bind to values owned by the constructed command.
- No package-level Cobra command or flag state.
- No `init()` registration.
- Shared command helpers belong in the owning package's `cmd.go`.
- Command-specific helpers belong in the command's own file.
- Do not create `wiring.go` or artificial `output.go` aggregation files.

## Go and comment conventions

- Go 1.27.1 syntax and standard library are the baseline.
- Prefer `errors.AsType`, `errors.Join`, `slices`, `maps`, and iterator helpers where appropriate.
- Use short, consistent receivers: `c` for `Client`, `i` for `Instance`, `m` for `Manager`, `t` for `TableWriter`.
- Do not mix pointer and value receivers on one type.
- Do not use named returns.
- Wrap errors with lowercase context and `%w`.
- Use sentinel errors for matchable failure categories.
- Every Go file requires the copyright and SPDX header.
- Every declaration requires an identifier-first comment.
- Non-test functions use `Parameters:` and `Returns:` sections when applicable.
- Test functions have behavioral-summary comments only.
- Test helpers document only meaningful non-`t` parameters and real return values.
- Omit empty sections; never write `None`.

## Testing

- Unit tests belong in the package under test.
- Integration and contract tests belong in the external `_test` package when they exercise public behavior.
- Use `httptest.NewTestServer` for real HTTP contract coverage.
- Use `t.Context()` and `t.Parallel()` unless mutating process-global Viper state.
- `pkg/adguard` domains have unit, integration, and fuzz files named:
  - `<domain>_test.go`
  - `<domain>_integration_test.go`
  - `<domain>_fuzz_test.go`
- Public library integration suites must cover request contracts, decoding, optional presence, malformed input, structured errors, response limits, and cancellation.
- Fuzz targets must be bounded, offline, deterministic, and assert structured error kinds.
- Preserve minimized fuzz corpora under `pkg/**/testdata/fuzz/`.

## Mockery

- Service interfaces live in their `pkg/adguard` domain files.
- Interfaces remain small and feature-scoped.
- Compile-time assertions that `*adguard.Client` satisfies each interface stay beside the interface.
- Run `task mock` after interface changes.
- Generated mocks are disposable outputs; never edit them manually.
- Use generated mocks in consumer/application tests, not in `pkg/adguard` HTTP contract tests.

## Configuration safety

- Use `example/config.yaml` as the starting template. It documents every credential source.
- The lookup order is explicit `--config`, the per-user configuration file, then `./config.yaml`. The per-user file is `agh-cli/config.yaml` under the platform configuration root: `$XDG_CONFIG_HOME/agh-cli/config.yaml` (defaulting to `~/.config/agh-cli/config.yaml`) on Unix, `~/Library/Application Support/agh-cli/config.yaml` on macOS, and `%AppData%\agh-cli\config.yaml` on Windows. Resolve it with [os.UserConfigDir], never a hardcoded home path.
- The first write creates the per-user configuration file and its directory. A write never invents a path in the current working directory.
- Resolve the configuration file exactly once, in `internal/app`, and publish the outcome for both the read and the write. The root command must not configure a second search of its own, because two resolutions drift and the explicit path then behaves differently from the default one.
- A file with no content is not an error. Whitespace alone, including a tab, is an empty configuration that the first write replaces, because YAML forbids a tab as indentation and would otherwise reject a file that is visually empty.
- Every configuration error names the file that failed.
- A write preserves top-level keys agh-cli does not own, re-emitting them ahead of the keys it owns. Never silently drop an annotation or a key another tool reads.
- A write follows a symlinked configuration to its target. A rename onto the link path would replace the link and leave the file the operator named unchanged.
- A write refuses to overwrite a file that changed after it was read, so a concurrent editor or a second process cannot have its change discarded silently.
- Instances that fail validation are reported as a warning at load, never as a load failure, because a hard failure would make a broken instance impossible to remove.
- Use `chmod 600 config.yaml` for files containing credentials. The configuration manager already writes mode 600.
- Never treat local test credentials as repository content, and never include them in output, tests, or commits.

## Credential safety

- Instance passwords belong in the operating system credential store by default. `internal/credentials` wraps it behind the project-owned `Store` interface.
- Do not expose the keyring library's error taxonomy or platform-specific behavior through `cmd`, `internal/app`, or `pkg/adguard`. Wrap it in `internal/credentials`.
- A secret must never appear in an error, a status value, a log line, a test fixture, or documentation. Errors may carry the service, the credential key, the file path, or the variable name.
- Supported `credential.source` values are `keyring`, `file`, `env`, `plaintext`, and `none`. A configured source is the only source that is read; an unreadable credential is an error, never a fallback.
- `file` and `env` sources belong to an external system. Never delete, rewrite, or detach them from the CLI.
- `agh-cli instance credentials` has no `get` subcommand on purpose. `agh-cli instance add` publishes no username or password flag, and none may be added back. Do not add a command that prints a secret or a flag that accepts one as an argument.
- Rotation is a repeated `agh-cli instance credentials password set <instance>`, not a separate command.
- The username and the password are managed independently, and each owns its own command subtree: `agh-cli instance credentials username set|status|clear` and `agh-cli instance credentials password set|status|clear`. A username is configuration and is written to the configuration file; a password is a secret and lives in the credential store. Never let one write touch the other.
- `agh-cli instance credentials migrate` stays at the group level, because it moves a whole instance from the legacy model, where a username was written at creation alongside a plaintext password, onto the current one. Do not move it into either subtree.

## Documentation and generated content

- `tools/docgen` introspects `cmd.NewRootCommand()`.
- Run `task docs` after command metadata or flag changes.
- Run `task docs-check` before submitting command changes.
- `README.md`, `www/content/_index.md`, `www/content/getting-started/_index.md`, and `example/config.yaml` are hand-maintained; `www/content/cli-reference/**` is generated.
- Hugo documentation lives under `www` and requires Hugo Extended.
- Never commit `www/public/`, root `public/`, `.hugo_build.lock`, `bin/`, or `dist/`.

## Validation

Use the configured autofix behavior for the normal lint pass:

```bash
golangci-lint run --fix --config build/golangci-lint/golangci-lint.yaml ./...
```

Use the CLI flag for non-mutating verification only:

```bash
golangci-lint run --fix=false --config build/golangci-lint/golangci-lint.yaml ./...
```

Before completion, run:

```bash
gofmt -w <changed Go files>
go test -race -covermode=atomic ./...
go vet ./...
staticcheck ./...
task docs-check
```

`make ci-check` is a local subset of CI, not a full replacement for the GitHub Actions checks.
