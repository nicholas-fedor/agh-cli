---
title: Add
description: Add a new instance configuration without any credentials. Set the administrator username with 'agh-cli instance credentials username set <instance> <username...
type: docs
---

Add a new instance configuration without any credentials. Set the
administrator username with 'agh-cli instance credentials username set
<instance> <username>' and the password with 'agh-cli instance credentials
password set <instance>'. The password is read from a hidden prompt, so
it never appears in a process listing or shell history.

### Usage

```bash
agh-cli instance add <instance> <host>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--scheme` | `-s` | https | string | HTTP scheme |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
