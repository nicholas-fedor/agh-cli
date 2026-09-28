---
title: Add
description: Add a new instance configuration without any credentials. Set the administrator username with 'agh-cli instance credentials username set <instance> <username...
type: docs
---

Add a new instance configuration without any credentials. Set the
administrator username with 'agh-cli instance credentials username set
<instance> <username>' and the password with 'agh-cli instance credentials
password set <instance>'. No command accepts the password as an argument,
and the hidden prompt keeps it out of your shell history and out of any
process listing. When standard input is redirected instead, keep the
literal out of the command line yourself.

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
