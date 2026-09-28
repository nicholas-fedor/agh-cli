---
title: Status
description: Report the configured AdGuard Home administrator username. With no argument every configured instance is reported in configuration order. A username is confi...
type: docs
---

Report the configured AdGuard Home administrator username. With no
argument every configured instance is reported in configuration order.
A username is configuration rather than a secret, so reporting it is
safe; use 'agh-cli instance credentials password status' for the password
side.

### Usage

```bash
agh-cli instance credentials username status [instance]
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--json` |  | false | bool | render the report as JSON |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
