---
title: Migrate
description: Move the legacy plaintext password of every configured instance that declares no credential source into the operating system credential store. Use --dry-run ...
type: docs
---

Move the legacy plaintext password of every configured instance that declares no credential source into the operating system credential store. Use --dry-run first to preview the change. A password reaches the credential store before it is removed from the configuration, and no password is ever printed.

### Usage

```bash
agh-cli instance credentials migrate
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--dry-run` |  | false | bool | report the change without writing to the store or the configuration |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
