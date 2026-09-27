---
title: Add
description: Add wildcard rewrite rules for a zone
type: docs
---

### Usage

```bash
agh-cli rewrite wildcard add <domain>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
