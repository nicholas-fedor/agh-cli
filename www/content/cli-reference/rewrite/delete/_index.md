---
title: Delete
description: Delete a rewrite rule
type: docs
---

### Usage

```bash
agh-cli rewrite delete <domain>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--answer` | `-A` | "" | string | answer/IP to delete |
| `--enabled` | `-e` | true | bool | rule enabled state |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
