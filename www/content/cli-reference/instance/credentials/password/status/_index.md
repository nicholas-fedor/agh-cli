---
title: Status
description: Report the credential store backend, its availability, and the configured credential source and presence of one instance, or of every configured instance. A ...
type: docs
---

Report the credential store backend, its availability, and the
configured credential source and presence of one instance, or of every
configured instance. A stored secret is never reported.

### Usage

```bash
agh-cli instance credentials password status [instance]
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--json` |  | false | bool | render the report as JSON |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
