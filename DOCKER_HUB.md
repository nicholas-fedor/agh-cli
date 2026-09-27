<!-- markdownlint-disable MD013 MD033 MD041 -->

<div align="center">
  <img src="https://raw.githubusercontent.com/nicholas-fedor/agh-cli/main/.github/assets/agh-cli.svg" alt="agh-cli logo" width="150">
</div>

# agh-cli

[![Docker Image Version](https://img.shields.io/docker/v/nickfedor/agh-cli?logo=docker&label=Docker)](https://hub.docker.com/r/nickfedor/agh-cli)
[![Docker Image Size](https://img.shields.io/docker/image-size/nickfedor/agh-cli/latest?logo=docker)](https://hub.docker.com/r/nickfedor/agh-cli)
[![Docker Pulls](https://img.shields.io/docker/pulls/nickfedor/agh-cli?logo=docker)](https://hub.docker.com/r/nickfedor/agh-cli)
[![License](https://img.shields.io/github/license/nicholas-fedor/agh-cli?label=License)](https://github.com/nicholas-fedor/agh-cli/blob/main/LICENSE.md)
[![Go Version](https://img.shields.io/github/go-mod/go-version/nicholas-fedor/agh-cli?logo=go&label=Go)](https://github.com/nicholas-fedor/agh-cli)
[![Latest Release](https://img.shields.io/github/v/release/nicholas-fedor/agh-cli?logo=github)](https://github.com/nicholas-fedor/agh-cli/releases/latest)

`agh-cli` is a command-line client for managing multiple AdGuard Home instances from one place. It supports client, filtering, rewrite, protection, DNS, DHCP, TLS, status, statistics, query-log, and credential-management workflows.

## Highlights

- Manage multiple AdGuard Home instances in one command
- Manage clients, access lists, filtering, rewrites, and protections
- Inspect status, statistics, and query logs
- Store credentials in the OS keyring, mounted secret files, environment variables, or a protected configuration file
- Cross-platform public Go client available as `github.com/nicholas-fedor/agh-cli/pkg/adguard`
- Signed, immutable release images with published checksums, SBOMs, and provenance attestations
- Minimal `scratch` runtime image running as a non-root user

## Supported Platforms

Published images support:

- `linux/amd64`
- `linux/386`
- `linux/arm/v6`
- `linux/arm64/v8`
- `linux/riscv64`

## Quick Start

Pull the latest image:

```bash
docker pull nickfedor/agh-cli:latest
```

Display the CLI version:

```bash
docker run --rm nickfedor/agh-cli:latest version
```

List configured instances:

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  nickfedor/agh-cli:latest \
  --config /config.yaml instance list
```

List rewrite rules across every configured instance:

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  nickfedor/agh-cli:latest \
  --config /config.yaml rewrite list --all
```

## Configuration

The container does not contain host configuration. Mount a configuration file and pass its path with `--config`:

```yaml
instances:
  default:
    host: adguard.example.com
    scheme: https
    username: admin
```

Protect local configuration files because they may contain credentials:

```bash
chmod 600 config.yaml
```

### Environment Credential

Containers do not have access to the host's desktop keyring. Use an environment credential for container deployments:

```yaml
instances:
  default:
    host: adguard.example.com
    username: admin
    credential:
      source: env
      env: ADGUARD_PASSWORD
```

```bash
docker run --rm \
  -e ADGUARD_PASSWORD \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  nickfedor/agh-cli:latest \
  --config /config.yaml filtering status --instance default
```

### Mounted Secret File

Docker and Kubernetes secrets can be read without placing the secret value in the image or command line:

```yaml
instances:
  default:
    host: adguard.example.com
    username: admin
    credential:
      source: file
      path: /run/secrets/agh-cli-default
```

```bash
docker run --rm \
  -e ADGUARD_PASSWORD \
  --mount type=bind,source="$(pwd)/adguard-password",target=/run/secrets/agh-cli-default,readonly \
  -v "$(pwd)/config.yaml:/config.yaml:ro" \
  nickfedor/agh-cli:latest \
  --config /config.yaml filtering status --instance default
```

`agh-cli` opens mounted secret files read-only and never modifies them.

## Image Variants

| Tag           | Description                           |
| ------------- | ------------------------------------- |
| `latest`      | Latest stable release                 |
| `0.1.0`       | Specific stable release patch version |
| `0.1`         | Current minor release                 |
| `0`           | Current major release                 |
| `amd64-0.1.0` | Platform-specific amd64 image         |
| `<digest>`    | Immutable content-addressed image     |

For production deployments, prefer a version tag or digest instead of `latest`.

## Security and Provenance

Stable images are published with:

- Docker Content Trust-compatible Cosign signatures
- SPDX SBOMs
- `checksums.txt` and image digest manifests
- GitHub artifact attestations
- Non-root execution as UID/GID `1000`

Verify a downloaded image with Cosign before deployment:

```bash
cosign verify ghcr.io/nicholas-fedor/agh-cli:0.1.0
```

The GHCR image is available at:

```text
ghcr.io/nicholas-fedor/agh-cli
```

## Links

- [Source repository](https://github.com/nicholas-fedor/agh-cli)
- [Documentation](https://agh-cli.nickfedor.com/)
- [CLI reference](https://agh-cli.nickfedor.com/cli-reference/)
- [Releases](https://github.com/nicholas-fedor/agh-cli/releases)
- [Issue tracker](https://github.com/nicholas-fedor/agh-cli/issues)
- [Security policy](https://github.com/nicholas-fedor/agh-cli/security/policy)
- [Go library documentation](https://pkg.go.dev/github.com/nicholas-fedor/agh-cli)

## License

`agh-cli` is licensed under the GNU Affero General Public License v3.0 or later.
