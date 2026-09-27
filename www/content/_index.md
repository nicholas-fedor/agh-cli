---
title: agh-cli
description: A CLI for managing multiple AdGuard Home instances
---

## Introduction

**agh-cli** is a Go command-line client for managing multiple AdGuard Home instances. It provides CRUD operations for clients, DNS filtering configuration, and DNS rewrite rules, and can target any subset of the instances declared in a single YAML configuration file.

Instance passwords are read from the operating system credential store, from a read-only mounted secret file, or from an environment variable, and no command prints a stored secret.

The repository also publishes `pkg/adguard`, a standalone Go client for the complete AdGuard Home HTTP API that is independent of the CLI command layer.

## Features

- **Multi-instance management** — target any subset of configured AdGuard Home servers in one command
- **Client management** — list, add, update, and delete DHCP/DNS clients across instances
- **Filtering management** — read and modify filtering status, enabled/disabled services, and block/allow filter URLs
- **DNS rewrite rules** — full CRUD plus diff, wildcard rules, and rewrite settings
- **OS credential store** — instance passwords live in the macOS Keychain, the Linux and BSD Secret Service, or the Windows Credential Manager, behind `agh-cli instance credentials`
- **Public Go library** — `pkg/adguard` exposes the complete AdGuard Home API with context-aware calls, typed errors, bounded responses, and feature-scoped interfaces
- **YAML configuration** — single human-readable config file for all instance credentials and targets
- **Structured terminal output** — formatted tables for list operations
- **Multi-arch binaries** — built for linux, windows, and darwin across amd64, arm64, riscv64, and more
- **Cosign & SBOM** — release artifacts are signed and ship with SPDX SBOMs via GoReleaser

## Quick Start

While a Docker image is available, **agh-cli** is primarily intended for installation and use via bare-metal.

1. Install the `agh-cli` binary:

    ```bash
    tmp=$(mktemp)
    curl -sSfL https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/scripts/install.sh -o "$tmp" && sh "$tmp"
    rm -f "$tmp"
    ```

    See [Getting Started](/getting-started/) for packages, Docker, and building from source.

2. Add an instance without a password:

    ```bash
    agh-cli instance add default adguard.example.com --username admin
    ```

3. Store the password in the operating system credential store. `agh-cli` reads it from a hidden prompt, so it never appears in your shell history or in a process listing:

    ```bash
    agh-cli instance credentials set default
    ```

    The command writes the secret to the credential store first, then rewrites `./config.yaml` (or whichever file `--config` selected) to reference it:

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

    If `./config.yaml` is absent, `agh-cli` also searches `~/.config/agh-cli/config.yaml`.

4. Check the result:

    ```bash
    agh-cli instance credentials status
    ```

    No command prints a stored secret. `status` reports the backend, the service, and whether each instance's credential is `present`, `absent`, or `unknown`.

5. Run your first command:

    ```bash
    agh-cli filtering status --all
    agh-cli rewrite diff --all
    ```

Existing configurations that keep passwords in the file keep working. Restrict the file to its owner and migrate it when convenient:

```bash
chmod 600 config.yaml
agh-cli instance credentials migrate --dry-run
agh-cli instance credentials migrate
```

A host without a credential store session, such as most containers, can read the password from a mounted secret file under `/run/secrets` or from an environment variable instead. See [Getting Started](/getting-started/#headless-hosts-and-external-sources).

## CLI Reference

See the [CLI Reference](/cli-reference/) section for the full CLI reference.
