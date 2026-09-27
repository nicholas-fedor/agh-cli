---
title: Config
description: Update filtering configuration
type: docs
---

### Usage

```bash
agh-cli filtering config
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--enabled` | `-e` | true | bool | enable filtering |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |
| `--interval` | `-n` | 0 | int32 | update interval hours |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
