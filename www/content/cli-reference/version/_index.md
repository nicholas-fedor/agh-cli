---
title: Version
description: Print the application version, including commit SHA and build details.
type: docs
---

Print the application version, including commit SHA and build details.

### Usage

```bash
agh-cli version
```

### Examples

#### Print version

```bash
agh-cli version
```

#### Print detailed version info

```bash
agh-cli version --verbose
```

#### Print version as JSON

```bash
agh-cli version --json
```


### Command Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--json` | `-j` | false | bool | Output version information in JSON format |
| `--verbose` | `-v` | false | bool | Output detailed version information |

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
