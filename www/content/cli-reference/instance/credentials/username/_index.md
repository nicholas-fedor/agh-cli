---
title: Manage the administrator username of an instance
description: Manage the AdGuard Home administrator username of a configured instance. The username is configuration rather than a secret, so it is stored in the configura...
type: docs
---

Manage the AdGuard Home administrator username of a configured
instance. The username is configuration rather than a secret, so it is
stored in the configuration file and is independent of the password:
changing the username leaves a stored password untouched, and storing a
password leaves the username untouched.

### Usage

```bash
agh-cli instance credentials username
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
