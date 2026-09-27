---
title: Add
description: Add a rewrite rule
type: docs
---

### Usage

```bash
agh-cli rewrite add <domain> <answer>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--enabled` | `-e` | true | bool | enable rule |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
