---
title: Getting Started
type: docs
---

This guide walks you through installing agh-cli, configuring your AdGuard Home instances, and running your first commands.

## Prerequisites

- One or more [AdGuard Home](https://adguard.com/en/adguard-home/overview.html) instances reachable from your machine
- The admin username and password for those instances, if they require HTTP Basic Auth
- A running credential store session for the operating system credential store: the macOS Keychain, the Linux and BSD Secret Service, or the Windows Credential Manager. Hosts without one, such as most containers and many headless servers, can use a [mounted secret file or an environment variable](#headless-hosts-and-external-sources) instead
- [Go](https://go.dev/) 1.27+ (if installing from source)

## Installation

### Install script

```bash
tmp=$(mktemp)
curl -sSfL https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/scripts/install.sh -o "$tmp" && sh "$tmp"
rm -f "$tmp"

agh-cli version
```

The script downloads the latest release artifacts, verifies their SHA-256 checksums, and installs `agh-cli` using a native package when one is available or the release archive otherwise. On Linux this prefers a `.deb` / `.rpm` / `.apk` / Arch package when sudo is available, otherwise it installs the release archive into `$HOME/go/bin`.

| Variable       | Default                                  | Description                                         |
|----------------|------------------------------------------|-----------------------------------------------------|
| `VERSION`      | Latest release                           | Release tag such as `v0.1.0` or `0.1.0`             |
| `INSTALL_DIR`  | `$HOME/go/bin` or the previous directory | Destination for archive installations               |
| `INSTALL_TYPE` | `auto`                                   | Installation strategy: `auto`, `package`, `archive` |

Windows users should download the `.zip` asset from the [latest GitHub Release](https://github.com/nicholas-fedor/agh-cli/releases/latest).

### From Source

```bash
go install github.com/nicholas-fedor/agh-cli@latest
```

### Pre-built Binary

Download the latest archive or distro package from the [GitHub releases page](https://github.com/nicholas-fedor/agh-cli/releases).

### Docker

```bash
docker pull ghcr.io/nicholas-fedor/agh-cli:latest
# or
docker pull nickfedor/agh-cli:latest
```

Run it against a mounted configuration file:

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  ghcr.io/nicholas-fedor/agh-cli:latest \
  --config /config.yaml rewrite list --all
```

A container normally has no credential store session, so configure a `file` source and mount the secret read-only. See [Headless Hosts and External Sources](#headless-hosts-and-external-sources).

## Quick Start

By default, `agh-cli` looks for the per-user configuration file first and then `./config.yaml`. Add an instance, then set its username and store the secret in the operating system credential store:

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

`instance add` is also the step that creates the configuration, so a fresh install writes the per-user file and creates that directory rather than dropping a file into the directory you happened to run the command from.

- The hidden prompt keeps the password out of your shell history and out of any process listing.
- The command writes the secret to the credential store first, then rewrites the configuration to reference it, so the file ends up without a plaintext password:

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
```

Continue with the [configuration details](#configuration) below for additional instances and field descriptions, and with [Credentials](#credentials) for the full credential workflow.

## Configuration

`agh-cli` reads a YAML configuration file to discover AdGuard Home instances.

| Flag           | Default                     | Description                           |
|----------------|-----------------------------|---------------------------------------|
| `-c, --config` | none                        | Path to configuration file            |
|                | per-user configuration file | Searched before `./config.yaml`       |
|                | `./config.yaml`             | Searched when no per-user file exists |

The per-user configuration file is `agh-cli/config.yaml` under the platform configuration root:

| Platform             | Path                                                                                  |
|----------------------|---------------------------------------------------------------------------------------|
| Linux and other Unix | `$XDG_CONFIG_HOME/agh-cli/config.yaml`, defaulting to `~/.config/agh-cli/config.yaml` |
| macOS                | `~/Library/Application Support/agh-cli/config.yaml`                                   |
| Windows              | `%AppData%\agh-cli\config.yaml`                                                       |

- Set `XDG_CONFIG_HOME` to relocate the per-user file on Linux and other Unix systems.
- The first write creates the per-user file and its directory. An explicit `--config` path behaves the same way, so a missing file in a directory that does not exist yet is created too.
- A `--config` path that is a directory is refused by name.
- A file with no content is treated as missing, so a stray tab or a trailing space never blocks a command.
- Top-level keys `agh-cli` does not own are preserved, so an annotation or a key kept for another tool survives every write.
- A symlinked configuration is written through to the file it names, rather than the link being replaced.
- A file that changed after it was read is never overwritten, so a concurrent editor or a second `agh-cli` process cannot have its change discarded.
- An instance that cannot be used is reported as a warning at load, and stays removable.

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

Manage the instance definitions themselves with the `instance` command:

```bash
agh-cli instance list --all
agh-cli instance add default adguard.example.com
agh-cli instance remove backup
```

`agh-cli instance add` publishes no username or password flag. Both are authentication details, so they are set through the credentials commands: `agh-cli instance credentials username set <instance> <username>` writes the username to the configuration file, and `agh-cli instance credentials password set <instance>` stores the password in the operating system credential store. The two are independent, so either can be changed without touching the other.

### Credential Sources

The `credential` block selects exactly one source per instance. A configured source is the only source that is read: a failed lookup is an error rather than a silent fallback to another source, to the plaintext password, or to a different key.

| `source`    | Required field | Reads the password from                                      | `agh-cli` owns the secret     |
|-------------|----------------|--------------------------------------------------------------|-------------------------------|
| `keyring`   | `key`          | The OS credential store, under service `credentials.service` | Yes                           |
| `file`      | `path`         | A read-only mounted secret file                              | No, another system does       |
| `env`       | `env`          | An environment variable                                      | No, the environment does      |
| `plaintext` | `password`     | The `password` field of the same instance                    | Yes, but it stays in the file |
| `none`      | —              | Nothing; the instance sends no authentication                | Not applicable                |

Each source accepts only the field it consumes. A `keyring` stanza that also sets `path`, or a `file` stanza without an absolute `path`, is rejected when the configuration loads rather than partially applied. An unset `env` variable is an error, never a fallback.

`credentials.service` is the credential store namespace shared by every instance of the same operating system user. It defaults to `agh-cli`, and `--all` and the per-instance credential commands never touch any other service, so credentials belonging to other applications are never affected.

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

## Credentials

`agh-cli instance credentials` manages the two halves of instance authentication. A username is configuration and lives in the configuration file; a password is a secret and lives in the operating system credential store. Each has its own `set`, `status`, and `clear`, so either can be changed without disturbing the other. `migrate` sits at the group level because it moves a whole instance from the legacy model.

| Command                                                           | Description                                                |
|-------------------------------------------------------------------|------------------------------------------------------------|
| `agh-cli instance credentials username set <instance> <username>` | Set the administrator username in the configuration file   |
| `agh-cli instance credentials username status [instance]`         | Report the configured username                             |
| `agh-cli instance credentials username clear <instance>`          | Remove the administrator username                          |
| `agh-cli instance credentials password set <instance>`            | Store a secret and point the instance at it                |
| `agh-cli instance credentials password status [instance]`         | Report source, target, and presence, never the secret      |
| `agh-cli instance credentials password clear <instance>`          | Remove a stored credential and its configuration reference |
| `agh-cli instance credentials password clear --all`               | Remove every credential of the configured service          |
| `agh-cli instance credentials migrate`                            | Move an instance from the legacy model onto this one       |

| Flag        | Commands                             | Description                                                       |
|-------------|--------------------------------------|-------------------------------------------------------------------|
| `--key`     | `password set`                       | Credential key; defaults to the instance name                     |
| `-y, --yes` | `password set`, `password clear`     | Skip the confirmation, for non-interactive use                    |
| `--all`     | `password clear`                     | Remove every credential of the configured service                 |
| `--json`    | `username status`, `password status` | Render the report as JSON                                         |
| `--dry-run` | `migrate`                            | Report the change without writing to the store or the config file |

There is deliberately **no** `get` command. No command prints a stored secret, so `status` is safe to run in a shared terminal or a captured log. When a request needs the password, `agh-cli` reads it from the store and sends it.

### Storing a Credential

Add the instance first, then set the username and store the secret:

```bash
agh-cli instance add default adguard.example.com
agh-cli instance credentials username set default admin
agh-cli instance credentials password set default
```

`set` reads the password from a hidden prompt. When standard input is redirected, such as in a script, it reads the secret from standard input instead and echoes nothing:

```bash
printf '%s' "$AGH_ADMIN_PASSWORD" | agh-cli instance credentials password set default --yes
```

- The secret is read before the confirmation, so declining the prompt stores nothing and the value is dropped immediately.
- `--yes` pre-accepts the confirmation. It is the only way a redirected workflow can proceed, because a prompt needs a terminal.
- One trailing newline is stripped from a redirected secret, so a password that genuinely ends in a newline round-trips through a double redirect.
- An empty secret is refused before the store is touched.
- The credential store write happens first and `config.yaml` is rewritten only afterwards, so a failed write leaves the instance exactly as it was. A secret the configuration could not record is removed again.
- `--key` stores the secret under a key other than the instance name.

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

Presence is `present`, `absent`, or `unknown`.

- A `file` or `env` source reports `unknown`, because `agh-cli` does not read a secret owned by another system just to answer a status question.
- `available: false` means a credential store read failed.

### Rotating a Credential

Rotation is a second `set` for the same instance. The store is read first, so a write refuses to guess whether it would replace an existing credential, and the report names the outcome:

```bash
agh-cli instance credentials password set default
```

```text
Password:
Replaced credential for instance "default" in keyring service "agh-cli" with key "default".
```

- If the configuration file could not be rewritten, `agh-cli` warns that the plaintext password is still on disk and that the command is retryable. Run it again and the second attempt reports `Replaced` and saves successfully.

### Removing a Credential

```bash
agh-cli instance credentials password clear default
agh-cli instance credentials password clear --all --yes
```

`clear` deletes the store entry first and removes the configuration reference afterwards, so the file never points at a secret that still exists.

- Clearing an absent credential is not an error, which makes a repeated clear safe.
- `--all` deletes everything under the configured service and deliberately leaves the configuration alone, so a surviving reference becomes a visible error instead of a silent change of source. Detach each instance with its own `clear`.
- A `file` or `env` instance is refused, because `agh-cli` owns neither that secret nor the decision to stop using it. Change those instances by editing the configuration.

### Migrating Legacy Plaintext Passwords

A configuration that stores passwords in the file keeps working unchanged. Preview the move first:

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

Until you migrate, a legacy plaintext password sits in `config.yaml` in the clear. Keep the file readable only by its owner:

```bash
chmod 600 config.yaml
```

`agh-cli` rewrites the file with mode 600 when it saves, so a migrated configuration is never left group- or world-readable.

### Credential Service and Key Schema

| Setting               | Default       | Description                                                             |
|-----------------------|---------------|-------------------------------------------------------------------------|
| `credentials.service` | `agh-cli`     | Credential store namespace shared by every instance of the same OS user |
| `credential.key`      | instance name | Credential identity within that service                                 |

The key resolves in one order: the `--key` value passed to `set`, then the `credential.key` already configured for the instance, then the instance name. The key never embeds a host, so changing a host never requires re-entering a password.

The service is global to the operating system user rather than per configuration path, so a credential written through `./config.yaml` is visible to a later run that resolves the per-user configuration file.

### Headless Hosts and External Sources

A headless host, an SSH session, or a container usually has no usable credential store session, and a Linux host without a running Secret Service session reports the store as unavailable rather than falling back to another store. Point the instance at the system that already holds the secret instead:

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

`file` reads a mounted secret, which is how Docker, Kubernetes, systemd, and Vault hand over a password. The path must be absolute, must point at a regular file, and must be 64 KiB or smaller. `agh-cli` opens the file read-only, never writes to it, never changes its permissions, and never trims its contents, so a trailing newline written by the external system stays part of the password. Docker and Kubernetes normally mount secrets below `/run/secrets`, so the mount and the container user are part of the trust boundary.

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  --mount type=bind,src="$(pwd)/admin-password",dst=/run/secrets/agh-cli/admin,readonly \
  ghcr.io/nicholas-fedor/agh-cli:latest \
  --config /config.yaml filtering status --instance dockerized
```

`set` and `clear` also need a terminal for the hidden prompt and the confirmation. In a non-interactive workflow, redirect the secret into `set` and pass `--yes`; on a host with no credential store at all, configure `file` or `env` instead of `keyring`.

## Basic Usage

### Managing Clients

```bash
# List clients across all instances
agh-cli client list --all

# Add a client to a specific instance
agh-cli client add laptop \
  --id AA-BB-CC-DD-EE-FF \
  --instance default

# Update and delete clients
agh-cli client update laptop --name my-laptop --instance default
agh-cli client delete laptop --instance default
```

### Managing Filtering

```bash
# Show filtering status per instance
agh-cli filtering status --all

# Set filtering parameters
agh-cli filtering config --all

# Add and remove filter URLs
agh-cli filtering add-url adguard-default "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" --all
agh-cli filtering remove-url "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt" --all
```

### Managing Rewrite Rules

```bash
# List rewrite rules
agh-cli rewrite list --all

# Add a rewrite rule
agh-cli rewrite add --domain ads.example.com --answer 192.0.2.10 --instance default

# Update and delete rules
agh-cli rewrite update --domain ads.example.com --answer 192.0.2.20 --instance default
agh-cli rewrite delete --domain ads.example.com --instance default

# Diff rules between two configured instances
agh-cli rewrite diff --instance default,backup

# Read and update rewrite settings
agh-cli rewrite settings get --instance default
agh-cli rewrite settings update --instance default
```

### Wildcard Rewrite Rules

```bash
agh-cli rewrite wildcard add --domain "*.example.com" --answer 192.0.2.10 --instance default
agh-cli rewrite wildcard delete --domain "*.example.com" --instance default
```

## Version

```bash
agh-cli version
agh-cli version --verbose
agh-cli version --json
```

## Updating

Update using the installation script:

```bash
tmp=$(mktemp)
curl -sSfL https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/scripts/install.sh -o "$tmp" && sh "$tmp" update
rm -f "$tmp"
```

## Uninstalling

Uninstall using the installation script:

```bash
tmp=$(mktemp)
curl -sSfL https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/scripts/install.sh -o "$tmp" && sh "$tmp" uninstall
rm -f "$tmp"
```

## Go Library

The repository publishes a reusable Go client at `pkg/adguard` that covers the complete AdGuard Home HTTP API independently of the CLI command layer.

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

## Next Steps

See the full [CLI reference](/cli-reference/) for all commands, flags, and advanced usage.
