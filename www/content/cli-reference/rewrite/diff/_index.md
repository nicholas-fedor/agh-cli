---
title: Diff
description: Diff rewrite rules between two configured instances, or between an instance and a local file. Specify two instances with --instance flags, or one instance wi...
type: docs
---

Diff rewrite rules between two configured instances, or between an instance and a local file.
Specify two instances with --instance flags, or one instance with --file.

### Usage

```bash
agh-cli rewrite diff [<instance> <instance>]
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--file` | `-f` | "" | string | path to YAML/JSON rewrite rules file |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |
| `--sort` | `-s` | domain | string | sort column (domain, answer, status) |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
