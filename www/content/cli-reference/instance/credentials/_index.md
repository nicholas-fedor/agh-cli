---
title: Manage instance authentication
description: Manage the authentication of configured instances. A username is configuration and lives in the configuration file; a password is a secret and lives in the o...
type: docs
---

Manage the authentication of configured instances. A username is
configuration and lives in the configuration file; a password is a secret
and lives in the operating system credential store. The two are managed
independently, so either can be changed without disturbing the other.
Use 'migrate' to move an instance written by an older release onto this
model.

### Usage

```bash
agh-cli instance credentials
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
