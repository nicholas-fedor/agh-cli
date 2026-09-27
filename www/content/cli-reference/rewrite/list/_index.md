---
title: List
description: List rewrite rules
type: docs
---

### Usage

```bash
agh-cli rewrite list
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |
| `--sort` | `-s` | domain | string | sort column (domain, answer, status) |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
