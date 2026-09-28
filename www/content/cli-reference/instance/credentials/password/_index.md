---
title: Manage the stored password of an instance
description: Store, inspect, and remove the AdGuard Home administrator password of a configured instance in the operating system credential store. The password is a secre...
type: docs
---

Store, inspect, and remove the AdGuard Home administrator password
of a configured instance in the operating system credential store. The
password is a secret, so it is never an argument and no command prints
it. The username is configuration and is managed separately by 'agh-cli
instance credentials username'.

### Usage

```bash
agh-cli instance credentials password
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
