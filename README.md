<!-- markdownlint-disable -->
<div align="center">

# agh-cli

<img src=".github/assets/agh-cli.svg" alt="agh-cli Logo" width="150">

CLI for managing multiple AdGuard Home instances

[![Latest Version](https://img.shields.io/github/tag/nicholas-fedor/agh-cli.svg)](https://github.com/nicholas-fedor/agh-cli/releases)
[![GoDoc](https://pkg.go.dev/badge/github.com/nicholas-fedor/agh-cli.svg)](https://pkg.go.dev/github.com/nicholas-fedor/agh-cli)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/nicholas-fedor/agh-cli)
![GitHub License](https://img.shields.io/github/license/nicholas-fedor/agh-cli)

</div>
<!-- markdownlint-restore -->

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
  - [Install Script](#install-script)
  - [Docker](#docker)
  - [Go Install](#go-install)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
  - [Config File](#config-file)
  - [Credential Sources](#credential-sources)
  - [Instance Selection](#instance-selection)
- [Credentials](#credentials)
  - [Storing a Credential](#storing-a-credential)
  - [Inspecting Credentials](#inspecting-credentials)
  - [Rotating a Credential](#rotating-a-credential)
  - [Removing a Credential](#removing-a-credential)
  - [Migrating Legacy Plaintext Passwords](#migrating-legacy-plaintext-passwords)
  - [Credential Service and Key Schema](#credential-service-and-key-schema)
  - [Headless and External Secret Sources](#headless-and-external-secret-sources)
- [Command Reference](#command-reference)
  - [Global Flags](#global-flags)
  - [Commands](#commands)
    - [`instance`](#instance)
    - [`instance credentials`](#instance-credentials)
    - [`client`](#client)
    - [`filtering`](#filtering)
    - [`rewrite`](#rewrite)
    - [`version`](#version)
- [Examples](#examples)
- [Docker](#docker-1)
  - [Using the published image](#using-the-published-image)
  - [Building locally](#building-locally)
- [Building from Source](#building-from-source)
  - [Prerequisites](#prerequisites)
  - [Build](#build)
- [Documentation](#documentation)
- [Go Library](#go-library)
- [Contributing](#contributing)
- [License](#license)

---

## Features

- **Public Go library** — `pkg/adguard` exposes the complete AdGuard Home API with context-aware calls, typed errors, bounded responses, and feature-scoped interfaces
- **Multi-instance management** — target any subset of configured AdGuard Home servers in one command
- **Client management** — list, add, update, and delete DHCP/DNS clients across instances
- **Filtering management** — read and modify filtering status, enabled/disabled services, and block/allow filter URLs
- **DNS rewrite rules** — full CRUD plus diff, wildcard rules, and rewrite settings
- **OS credential store** — instance passwords live in the macOS Keychain, the Linux and BSD Secret Service, or the Windows Credential Manager, behind `agh-cli instance credentials`
- **YAML configuration** — single human-readable config file for all instance credentials and targets
- **Structured terminal output** — formatted tables for list operations
- **Multi-arch binaries** — built for linux, windows, and darwin across amd64, arm64, riscv64, and more
- **Cosign & SBOM** — release artifacts are signed and ship with SPDX SBOMs via GoReleaser

---

## Installation

### Install Script

The install script downloads the latest release artifacts, verifies their SHA-256 checksums, and installs `agh-cli` using a native package when one is available or the release archive otherwise.

```bash
tmp=$(mktemp)
curl -sSfL https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/scripts/install.sh -o "$tmp"
sh "$tmp"
rm -f "$tmp"

agh-cli version
```

Update or uninstall an existing archive installation:

```bash
tmp=$(mktemp)
curl -sSfL https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/scripts/install.sh -o "$tmp"
sh "$tmp" update
# or
sh "$tmp" uninstall
rm -f "$tmp"
```

| Variable       | Default                                  | Description                                         |
|----------------|------------------------------------------|-----------------------------------------------------|
| `VERSION`      | Latest release                           | Release tag such as `v0.1.0` or `0.1.0`             |
| `INSTALL_DIR`  | `$HOME/go/bin` or the previous directory | Destination for archive installations               |
| `INSTALL_TYPE` | `auto`                                   | Installation strategy: `auto`, `package`, `archive` |

Windows users should download the `.zip` asset from the [latest GitHub Release](https://github.com/nicholas-fedor/agh-cli/releases/latest).

### Docker

```bash
docker pull ghcr.io/nicholas-fedor/agh-cli:latest
# or
docker pull nickfedor/agh-cli:latest
```

### Go Install

```bash
go install github.com/nicholas-fedor/agh-cli@latest
```

---

## Quick Start

By default, `agh-cli` looks for the per-user configuration file first and then `./config.yaml`. Add an instance, then set its username and password through the credentials commands:

```bash
agh-cli instance add default adguard.example.com
agh-cli instance credentials username set default admin
agh-cli instance credentials password set default
```

The first command creates the configuration, so `instance add` is also the step that creates the per-user directory. `instance add` takes no credentials at all: the username and the password are set separately through the credential commands. No command accepts the password as an argument, and the hidden prompt keeps it out of your shell history and out of any process listing. When standard input is redirected instead, keep the literal out of the command line yourself. `credentials password set` then rewrites the configuration to reference the credential store instead of a plaintext password. See [Credentials](#credentials) for the complete workflow.

Compare DNS rewrite rules between AdGuard Home instances:

```bash
agh-cli rewrite diff --all
```

Or manage a specific instance:

```bash
agh-cli filtering status --instance default
```

---

## Configuration

`agh-cli` reads a YAML configuration file to discover AdGuard Home instances.

| Flag           | Default | Description                                        |
|----------------|---------|----------------------------------------------------|
| `-c, --config` | none    | Path to configuration file                         |
|                | per-user configuration file | Searched before `./config.yaml` |
|                | `./config.yaml` | Searched when no per-user file exists     |

The per-user configuration file is `agh-cli/config.yaml` under the platform configuration root:

| Platform | Path |
|----------|------|
| Linux and other Unix | `$XDG_CONFIG_HOME/agh-cli/config.yaml`, defaulting to `~/.config/agh-cli/config.yaml` |
| macOS | `~/Library/Application Support/agh-cli/config.yaml` |
| Windows | `%AppData%\agh-cli\config.yaml` |

Set `XDG_CONFIG_HOME` to relocate the per-user configuration on Linux and other Unix systems. The first command that writes a configuration creates this per-user file and its directory.

### Config File

```yaml
credentials:
  service: agh-cli

instances:
  default:
    host: adguard.example.com
    scheme: https
    username: admin
    credential:
      source: keyring
      key: default
  office:
    host: adguard.office.example.com
    scheme: http
    username: admin
    password: office-password
```

| Field        | Required | Default | Description                                               |
|--------------|----------|---------|-----------------------------------------------------------|
| `host`       | Yes      | —       | AdGuard Home host or IP                                   |
| `scheme`     | No       | `https` | `http` or `https`                                         |
| `username`   | No       | —       | Admin username for HTTP Basic Auth                        |
| `password`   | No       | —       | Legacy plaintext password for HTTP Basic Auth             |
| `credential` | No       | —       | Credential reference; when omitted the `password` is used |

`credentials.service` sets the credential store namespace for every instance and defaults to `agh-cli`. See [example/config.yaml](example/config.yaml) for a commented template covering every source.

### Credential Sources

The `credential` block selects exactly one source per instance. A configured source is the only source that is read, so a failed lookup is an error rather than a silent fallback to another source, to the plaintext password, or to a different key.

| `source`    | Required field | Reads the password from                                      | `agh-cli` owns the secret     |
|-------------|----------------|--------------------------------------------------------------|-------------------------------|
| `keyring`   | `key`          | The OS credential store, under service `credentials.service` | Yes                           |
| `file`      | `path`         | A read-only mounted secret file, such as `/run/secrets/…`    | No, another system does       |
| `env`       | `env`          | An environment variable                                      | No, the environment does      |
| `plaintext` | `password`     | The `password` field of the same instance                    | Yes, but it stays in the file |
| `none`      | —              | Nothing; the instance sends no authentication                | Not applicable                |

Each source accepts only the field it consumes. A `keyring` stanza that also sets `path`, or a `file` stanza without an absolute `path`, is rejected at load time rather than partially applied. A `file` source must point at an absolute path to a regular file of 64 KiB or less; agh-cli opens it read-only, never writes to it, and never trims its contents, so a trailing newline written by the external system stays part of the password. An unset `env` variable is an error, never a fallback.

### Instance Selection

Most commands accept the following flags to choose which instances to operate against:

| Flag                     | Description                                  |
|--------------------------|----------------------------------------------|
| `-a, --all`              | Target **all** configured instances          |
| `-i, --instance <names>` | Target specific named instances (repeatable) |

Selection precedence:

1. `--all`
2. `--instance` names
3. `default` instance (if present)
4. single-instance resolution (error if ambiguous)

---

## Credentials

`agh-cli instance credentials` manages the two halves of instance authentication. A username is configuration and lives in the configuration file; a password is a secret and lives in the operating system credential store: the macOS Keychain, the Linux and BSD Secret Service, or the Windows Credential Manager, depending on the platform. A Linux host without a running Secret Service session reports the store as unavailable rather than falling back to another store.

Each half has its own `set`, `status`, and `clear`, so either can be changed without disturbing the other. `migrate` sits at the group level because it moves a whole instance from the legacy model, where a username was written at creation alongside a plaintext password.

| Command                                                            | Description                                            |
|--------------------------------------------------------------------|--------------------------------------------------------|
| `agh-cli instance credentials username set <instance> <username>` | Set the administrator username in the config file      |
| `agh-cli instance credentials username status [instance]`         | Report the configured username                         |
| `agh-cli instance credentials username clear <instance>`          | Remove the administrator username                      |
| `agh-cli instance credentials password set <instance>`            | Store a secret and point the instance at it            |
| `agh-cli instance credentials password status [instance]`         | Report source, target, and presence, never the secret  |
| `agh-cli instance credentials password clear <instance>`          | Remove a stored credential and its reference           |
| `agh-cli instance credentials password clear --all`               | Remove every credential of the service                 |
| `agh-cli instance credentials migrate`                            | Move an instance from the legacy model onto this one   |

There is deliberately **no** `get` command. No command prints a stored secret, so `status` is safe to run in a shared terminal or a captured log. When an AdGuard Home request needs the password, agh-cli reads it from the store and sends it; the value never appears in output.

### Storing a Credential

Add the instance first, then set the username and store the secret:

```bash
agh-cli instance add default adguard.example.com
agh-cli instance credentials username set default admin
agh-cli instance credentials password set default
```

```text
Password:
Store this credential for instance "default"? [y/N]: y
Stored credential for instance "default" in keyring service "agh-cli" with key "default".
```

The username and the password are managed independently. `credentials username set` writes the username to the configuration file and never touches the credential store, so changing a username leaves a stored password working. `credentials password set` writes only the credential store entry and the reference to it, so it never disturbs the username. The username is an ordinary argument because it is not a secret; the password is never an argument at all.

`set` reads the password from a hidden prompt. When standard input is redirected, such as in a script, it reads the secret from standard input instead and echoes nothing:

```bash
printf '%s' "$AGH_ADMIN_PASSWORD" | agh-cli instance credentials password set default --yes
```

The secret is read before the confirmation, so declining the prompt stores nothing and the value is dropped immediately. `--yes` (`-y`) pre-accepts the confirmation, which is the only way a redirected workflow can proceed, because a prompt needs a terminal. One trailing newline is stripped from a redirected secret, so a password that genuinely ends in a newline round-trips through a double redirect. An empty secret is refused before the store is touched.

The command writes the credential store entry first and rewrites `config.yaml` only afterwards, so a failed write leaves the instance exactly as it was. Use `--key` to store the secret under a key other than the instance name.

### Inspecting Credentials

```bash
# Every configured instance
agh-cli instance credentials password status

# One instance, as JSON
agh-cli instance credentials password status default --json
```

```text
backend: keyring
service: agh-cli
available: true
instance "default": source keyring, key "default", present
instance "office": source file, path "/run/secrets/agh-cli/office", unknown
instance "backup": source plaintext, present
```

Presence is `present`, `absent`, or `unknown`. A `file` or `env` source reports `unknown` because agh-cli does not read a secret owned by another system just to answer a status question, and `available: false` means a keyring read failed.

### Rotating a Credential

Rotation is a second `set` for the same instance. The store is read first, so a write refuses to guess whether it would replace an existing credential, and the report names the outcome:

```bash
agh-cli instance credentials password set default
```

```text
Password:
Replaced credential for instance "default" in keyring service "agh-cli" with key "default".
```

If the configuration file could not be rewritten, agh-cli warns that the plaintext password is still on disk and the command is retryable; run it again and the second attempt reports `Replaced` and saves successfully.

### Removing a Credential

```bash
agh-cli instance credentials password clear default
agh-cli instance credentials password clear --all --yes
```

`clear` deletes the store entry first and removes the configuration reference afterwards, so the file never points at a secret that still exists. Clearing an absent credential is not an error, which makes a repeated clear safe. `--all` deletes everything under the configured service and deliberately leaves the configuration alone, so a surviving reference becomes a visible error instead of a silent change of source; detach each instance with its own `clear`.

A `file` or `env` instance is refused, because agh-cli owns neither that secret nor the decision to stop using it. Change those instances by editing the configuration.

### Migrating Legacy Plaintext Passwords

A configuration that stores passwords in the file keeps working. Preview the move first:

```bash
agh-cli instance credentials migrate --dry-run
```

```text
would migrate "legacy" to keyring key "legacy"
would migrate "backup" to keyring key "backup"
backend: keyring
service: agh-cli
nothing was written: 2 credential(s) would be migrated
```

Then apply it:

```bash
agh-cli instance credentials migrate
```

Migration is explicit, because a normal read never migrates implicitly. It selects every instance that has no `credential` block and a non-empty `password`, and skips any instance that already declares a source, so a configured source is never changed silently. For each instance the password reaches the credential store before it is removed from the configuration, so a failed write leaves that instance unchanged and its plaintext password keeps working. The file is written once at the end, and no password is ever printed.

Until you migrate, a legacy plaintext password is stored in `config.yaml` in the clear. Keep the file readable only by its owner, and keep the template, `example/config.yaml`, free of real values:

```bash
chmod 600 config.yaml
```

agh-cli rewrites the file with mode 600 when it saves, so a migrated configuration is never left group- or world-readable.

### Credential Service and Key Schema

| Setting               | Default       | Description                                                             |
|-----------------------|---------------|-------------------------------------------------------------------------|
| `credentials.service` | `agh-cli`     | Credential store namespace shared by every instance of the same OS user |
| `credential.key`      | instance name | Keyring credential identity within that service                         |

The key is resolved in one order: the `--key` value passed to `set`, then the `credential.key` already configured for the instance, then the instance name. The key never embeds a host, so changing a host never requires re-entering a password.

`--all` and the per-instance commands only ever touch the configured service, so credentials belonging to other applications are never affected. The service is global to the operating system user rather than per configuration path, so a credential written through `./config.yaml` is visible to a later run that resolves the per-user configuration file.

### Headless and External Secret Sources

A headless host, an SSH session, or a container usually has no usable credential store session. Two options keep the secret out of the file:

```yaml
instances:
  dockerized:
    host: adguard.internal
    username: admin
    credential:
      source: file
      path: /run/secrets/agh-cli/admin
  headless:
    host: adguard.lan
    username: admin
    credential:
      source: env
      env: AGH_ADMIN_PASSWORD
```

`set` and `clear` also need a terminal for the hidden prompt and the confirmation. In a non-interactive workflow, redirect the secret into `set` and pass `--yes`; on a host with no credential store at all, configure `file` or `env` instead of `keyring`.

---

## Command Reference

```bash
agh-cli [global flags] <command> [subcommand] [flags]
```

### Global Flags

| Flag                  | Description                                 |
|-----------------------|---------------------------------------------|
| `-c, --config string` | Path to config file (default `config.yaml`) |
| `-h, --help`          | Help for `agh-cli`                          |

### Commands

#### `instance`

Manage the AdGuard Home instance definitions in your config file.

| Command                                 | Description                        |
|-----------------------------------------|------------------------------------|
| `agh-cli instance list [--all]`         | List configured instance names     |
| `agh-cli instance add <instance> <host>` | Add a new instance, without credentials |
| `agh-cli instance remove <instance>`    | Remove an instance                 |

`instance add` publishes no username or password flag. Both are authentication details, so they are set through the credentials commands.

#### `instance credentials`

Manage the two halves of instance authentication. See [Credentials](#credentials) for the full workflow.

| Command                                                            | Description                                                |
|--------------------------------------------------------------------|------------------------------------------------------------|
| `agh-cli instance credentials username set <instance> <username>` | Set the administrator username in the configuration file |
| `agh-cli instance credentials username status [instance]`         | Report the configured username                            |
| `agh-cli instance credentials username clear <instance>`          | Remove the administrator username                         |
| `agh-cli instance credentials password set <instance>`            | Store a secret from a hidden prompt or standard input      |
| `agh-cli instance credentials password status [instance]`         | Report source, target, and presence, never the secret      |
| `agh-cli instance credentials password clear <instance>`          | Remove a stored credential and its configuration reference |
| `agh-cli instance credentials password clear --all`               | Remove every credential of the configured service          |
| `agh-cli instance credentials migrate`                            | Move an instance from the legacy model onto this one      |

| Flag        | Commands       | Description                                                       |
|-------------|----------------|-------------------------------------------------------------------|
| `--key`     | `password set` | Credential key; defaults to the instance name                     |
| `-y, --yes` | `password set`, `password clear` | Skip the confirmation, for non-interactive use            |
| `--all`     | `password clear` | Remove every credential of the configured service               |
| `--json`    | `username status`, `password status` | Render the report as JSON                            |
| `--dry-run` | `migrate`      | Report the change without writing to the store or the config file |

There is no `get` command; no command prints a stored secret.

#### `client`

Manage clients across AdGuard Home instances.

| Command                                              | Description    |
|------------------------------------------------------|----------------|
| `agh-cli client list [--all \| --instance <name>]`   | List clients   |
| `agh-cli client add [--all \| --instance <name>]`    | Add a client   |
| `agh-cli client delete [--all \| --instance <name>]` | Delete clients |
| `agh-cli client update [--all \| --instance <name>]` | Update clients |

#### `filtering`

Manage DNS filtering configuration per instance.

| Command                                  | Description                        |
|------------------------------------------|------------------------------------|
| `agh-cli filtering status`               | Show filtering status per instance |
| `agh-cli filtering config`               | Set filtering parameters           |
| `agh-cli filtering add-url <name> <url>` | Add a filter URL                   |
| `agh-cli filtering remove-url <url>`     | Remove a filter URL                |

#### `rewrite`

Manage DNS rewrite rules and their associated settings.

| Command                           | Description                                  |
|-----------------------------------|----------------------------------------------|
| `agh-cli rewrite list`            | List rewrite rules                           |
| `agh-cli rewrite add`             | Add a rewrite rule                           |
| `agh-cli rewrite delete`          | Delete rewrite rules                         |
| `agh-cli rewrite update`          | Update a rewrite rule                        |
| `agh-cli rewrite diff`            | Diff rules between instances or a local file |
| `agh-cli rewrite settings get`    | Return rewrite settings                      |
| `agh-cli rewrite settings update` | Update rewrite settings                      |
| `agh-cli rewrite wildcard add`    | Add wildcard rewrite rules                   |
| `agh-cli rewrite wildcard delete` | Delete wildcard rewrite rules                |

#### `version`

Print version and build information.

| Command                               | Description                         |
|----------------------------------------|-------------------------------------|
| `agh-cli version [--verbose \| --json]` | Print version and build information |

---

## Examples

```bash
# List configured instances
agh-cli instance list --all

# Store the credential of an instance in the OS credential store
agh-cli instance credentials password set default

# Report credential presence for every instance
agh-cli instance credentials password status

# Show filtering status across all instances
agh-cli filtering status --all

# Add a client to the default instance
agh-cli client add laptop \
  --id AA-BB-CC-DD-EE-FF \
  --instance default

# Compare rewrite rules between two configured instances
agh-cli rewrite diff --instance default,backup
```

---

## Docker

### Using the published image

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  ghcr.io/nicholas-fedor/agh-cli:latest \
  --config /config.yaml rewrite list --all
```

A container usually has no credential store session, so read the password from a mounted secret instead of the keyring:

```yaml
instances:
  home:
    host: adguard.example.com
    username: admin
    credential:
      source: file
      path: /run/secrets/agh-cli/admin
```

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  --mount type=bind,src="$(pwd)/admin-password",dst=/run/secrets/agh-cli/admin,readonly \
  ghcr.io/nicholas-fedor/agh-cli:latest \
  --config /config.yaml filtering status --instance home
```

`set`, `clear`, and `migrate` need a credential store session, so run them on a host that has one. Inside a container, the secret belongs to whatever mounted it.

### Building locally

```bash
make docker-build
docker run --rm agh-cli version
```

The Docker image is a minimal scratch-based binary with static linking. CA certificates and timezone data are layered via an intermediate Alpine stage.

---

## Building from Source

### Prerequisites

- Go 1.27+
- `make` or `task` (optional)

### Build

Using Make:

```bash
make build
```

Using Task:

```bash
task build
```

Binary Output:

```bash
bin/agh-cli
```

---

## Documentation

The full CLI reference is generated from the Cobra command tree and published with the Hugo documentation site.

- Documentation: <https://agh-cli.nickfedor.com/>
- CLI reference: <https://agh-cli.nickfedor.com/cli-reference/>

Regenerate or preview the site locally:

```bash
task docs
task docs-serve
```

`task docs-check` fails when the committed reference differs from the current command tree.

---

## Go Library

The repository publishes a reusable Go client at `pkg/adguard`. It covers the complete AdGuard Home HTTP API and is independent of the CLI command layer.

```go
package main

import (
 "context"
 "log"

 "github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

func main() {
 client, err := adguard.NewClient(
  "https://adguard.example.com",
  adguard.WithBasicAuth("admin", "password"),
 )
 if err != nil {
  log.Fatal(err)
 }

 status, err := client.Status(context.Background())
 if err != nil {
  log.Fatal(err)
 }

 log.Printf("AdGuard Home %s is running", status.Version)
}
```

Library highlights:

- Context-first APIs with configurable request timeouts.
- Basic authentication and secure redirect handling.
- Bounded JSON and binary response reads.
- Typed, inspectable errors.
- Explicit optional-field presence for filters, clients, and rewrite rules.
- Feature-scoped interfaces for clients, filtering, rewriting, DNS, DHCP, TLS, safety services, and more.
- Generated Mockery doubles for consumer-level unit tests.
- Offline fuzz, integration, and HTTP contract test coverage.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, code conventions, testing, documentation, commits, and release expectations.

Automated contributors must also follow [AGENTS.md](AGENTS.md).

---

## License

This project is licensed under the **GNU Affero General Public License v3.0**. See [LICENSE.md](LICENSE.md) for details.
