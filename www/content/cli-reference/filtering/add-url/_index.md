---
title: Add-url
description: Add a filter URL
type: docs
---

### Usage

```bash
agh-cli filtering add-url <name> <url>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |
| `--whitelist` | `-w` | false | bool | add to whitelist |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
