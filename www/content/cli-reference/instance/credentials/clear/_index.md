---
title: Clear
description: Remove a stored credential from the operating system credential store. Use --all to remove every credential of the configured service. A mounted secret file ...
type: docs
---

Remove a stored credential from the operating system credential store. Use --all to remove every credential of the configured service. A mounted secret file and an environment variable are owned by another system and are never removed here. Use --yes for a non-interactive workflow.

### Usage

```bash
agh-cli instance credentials clear <name>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` |  | false | bool | remove every credential of the configured service |
| `--yes` | `-y` | false | bool | remove the credential without asking for confirmation |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
