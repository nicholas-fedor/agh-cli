---
title: Add
description: Add a new instance configuration. Prefer adding the instance without a password and storing the credential with 'agh-cli instance credentials set'.
type: docs
---

Add a new instance configuration. Prefer adding the instance without a password and storing the credential with 'agh-cli instance credentials set'.

### Usage

```bash
agh-cli instance add <name> <host>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--password` | `-p` | "" | string | admin password (deprecated: run 'agh-cli instance add <name> <host>' without a password, then 'agh-cli instance credentials set <name>') |
| `--scheme` | `-s` | https | string | HTTP scheme |
| `--username` | `-u` | "" | string | admin username |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
