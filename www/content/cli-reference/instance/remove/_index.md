---
title: Remove
description: Remove an instance configuration and the password it kept in the operating system credential store. A mounted secret file, an environment variable, and a pas...
type: docs
---

Remove an instance configuration and the password it kept in the
operating system credential store. A mounted secret file, an environment
variable, and a password kept in the configuration file belong to the
operator or to another system, so nothing is deleted for them.

### Usage

```bash
agh-cli instance remove <instance>
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
