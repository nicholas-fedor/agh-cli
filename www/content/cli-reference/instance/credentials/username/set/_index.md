---
title: Set
description: Set the AdGuard Home administrator username of a configured instance. The change is written to the configuration file and never reaches the credential store,...
type: docs
---

Set the AdGuard Home administrator username of a configured instance.
The change is written to the configuration file and never reaches the
credential store, so a stored password keeps working. Use 'agh-cli
instance credentials password set <instance>' to change the password
without disturbing the username.

### Usage

```bash
agh-cli instance credentials username set <instance> <username>
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
