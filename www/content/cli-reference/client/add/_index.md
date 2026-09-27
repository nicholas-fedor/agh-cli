---
title: Add
description: Add a client
type: docs
---

### Usage

```bash
agh-cli client add <name>
```

### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--all` | `-a` | false | bool | target all instances |
| `--filtering` | `-f` | false | bool | enable filtering |
| `--id` | `-I` | [] | stringArray | client IDs (IP, CIDR, MAC, or ClientID) |
| `--instance` | `-i` | [] | stringSlice | target instance name(s) |
| `--parental` | `-p` | false | bool | enable parental control |
| `--safebrowsing` | `-s` | false | bool | enable safebrowsing |
| `--use-global` | `-g` | true | bool | use global settings |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
