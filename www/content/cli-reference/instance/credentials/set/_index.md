---
title: Set
description: Store the credential of a configured instance in the operating system credential store and point the instance at it. The secret is read from a hidden prompt,...
type: docs
---

Store the credential of a configured instance in the operating system credential store and point the instance at it. The secret is read from a hidden prompt, or from standard input when it is redirected, and it is never echoed or printed. Use --yes for a non-interactive workflow.

### Usage

```bash
agh-cli instance credentials set <name>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--key` |  | "" | string | credential key, defaults to the instance name |
| `--yes` | `-y` | false | bool | store the credential without asking for confirmation |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
