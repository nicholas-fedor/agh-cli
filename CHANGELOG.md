<!-- markdownlint-disable MD024 -->
# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Skip git validation on nightly builds by @nicholas-fedor in [#43](https://github.com/nicholas-fedor/agh-cli/pull/43)

### Chores

- Update module golang.org/x/sys to v0.49.0 by @renovate[bot] in [#61](https://github.com/nicholas-fedor/agh-cli/pull/61)
- Update nicholas-fedor/actionlint-action action to v1.0.19 by @renovate[bot] in [#57](https://github.com/nicholas-fedor/agh-cli/pull/57)
- Update nicholas-fedor/govulncheck-action action to v1.1.0 by @renovate[bot] in [#58](https://github.com/nicholas-fedor/agh-cli/pull/58)
- Lock file maintenance by @renovate[bot] in [#47](https://github.com/nicholas-fedor/agh-cli/pull/47)
- Update github/codeql-action digest to 24c5418 by @renovate[bot] in [#54](https://github.com/nicholas-fedor/agh-cli/pull/54)
- Update step-security/harden-runner action to v2.22.1 by @renovate[bot] in [#52](https://github.com/nicholas-fedor/agh-cli/pull/52)
- Update actions/upload-artifact action to v7.0.2 by @renovate[bot] in [#50](https://github.com/nicholas-fedor/agh-cli/pull/50)
- Update step-security/harden-runner action to v2.22.0 by @renovate[bot] in [#48](https://github.com/nicholas-fedor/agh-cli/pull/48)
- Update anchore/sbom-action action to v0.24.3 by @renovate[bot] in [#45](https://github.com/nicholas-fedor/agh-cli/pull/45)
- Update module github.com/imfing/hextra to v0.13.0 by @renovate[bot] in [#41](https://github.com/nicholas-fedor/agh-cli/pull/41)

## [0.1.1] - 2026-09-29

### Added

- Add Docker Hub repository overview by @nicholas-fedor in [#29](https://github.com/nicholas-fedor/agh-cli/pull/29)

### Changed

- Split username and password into command groups by @nicholas-fedor in [#33](https://github.com/nicholas-fedor/agh-cli/pull/33)
- Skip workflow linting for release tags by @nicholas-fedor in [#27](https://github.com/nicholas-fedor/agh-cli/pull/27)

### Chores

- Update nicholas-fedor/go-proxy-pull-action action to v1.1.52 by @renovate[bot] in [#37](https://github.com/nicholas-fedor/agh-cli/pull/37)

### Fixed

- Delete the stored password when removing an instance by @nicholas-fedor in [#39](https://github.com/nicholas-fedor/agh-cli/pull/39)
- Stop the configuration from losing data or blocking a command by @nicholas-fedor in [#35](https://github.com/nicholas-fedor/agh-cli/pull/35)
- Create the first config in the per-user configuration directory by @nicholas-fedor in [#31](https://github.com/nicholas-fedor/agh-cli/pull/31)

## [0.1.0] - 2026-09-27

### Changed

- Pass GoReleaser arguments without empty newlines by @nicholas-fedor in [#25](https://github.com/nicholas-fedor/agh-cli/pull/25)
- Handle clean changelog pull requests by @nicholas-fedor in [#24](https://github.com/nicholas-fedor/agh-cli/pull/24)
- Skip commit lint for changelog-only pull requests by @nicholas-fedor in [#22](https://github.com/nicholas-fedor/agh-cli/pull/22)
- Update pkg.go.dev after stable releases by @nicholas-fedor in [#18](https://github.com/nicholas-fedor/agh-cli/pull/18)
- Upload coverage to Codecov by @nicholas-fedor in [#8](https://github.com/nicholas-fedor/agh-cli/pull/8)
- Initialize agh-cli CLI and library by @nicholas-fedor

### Chores

- Lock file maintenance by @renovate[bot] in [#14](https://github.com/nicholas-fedor/agh-cli/pull/14)
- Pin dependencies by @renovate[bot] in [#1](https://github.com/nicholas-fedor/agh-cli/pull/1)
- Update dependency typescript to v7 by @renovate[bot] in [#11](https://github.com/nicholas-fedor/agh-cli/pull/11)
- Update actions/setup-go action to v7 by @renovate[bot] in [#10](https://github.com/nicholas-fedor/agh-cli/pull/10)
- Update commitlint monorepo to v21.2.3 by @renovate[bot] in [#9](https://github.com/nicholas-fedor/agh-cli/pull/9)
- Update alpine docker tag to v3.24.2 by @renovate[bot] in [#6](https://github.com/nicholas-fedor/agh-cli/pull/6)
- Update github/codeql-action digest to 2892aa5 by @renovate[bot] in [#5](https://github.com/nicholas-fedor/agh-cli/pull/5)
- Update actions/setup-go digest to 924ae3a by @renovate[bot] in [#2](https://github.com/nicholas-fedor/agh-cli/pull/2)

### Fixed

- Support absolute paths on Windows by @nicholas-fedor in [#20](https://github.com/nicholas-fedor/agh-cli/pull/20)

### New Contributors

- @github-actions[bot] made their first contribution in [#26](https://github.com/nicholas-fedor/agh-cli/pull/26)
- @nicholas-fedor made their first contribution in [#25](https://github.com/nicholas-fedor/agh-cli/pull/25)
- @renovate[bot] made their first contribution in [#14](https://github.com/nicholas-fedor/agh-cli/pull/14)

## Compare Releases

- [unreleased](https://github.com/nicholas-fedor/agh-cli/compare/v0.1.1...HEAD)
- [0.1.1](https://github.com/nicholas-fedor/agh-cli/compare/v0.1.0...v0.1.1)

<!-- generated by git-cliff -->
