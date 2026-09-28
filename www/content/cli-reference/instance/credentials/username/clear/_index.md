---
title: Clear
description: Remove the AdGuard Home administrator username of a configured instance. Only the username is removed, so a stored password keeps working. Use 'agh-cli insta...
type: docs
---

Remove the AdGuard Home administrator username of a configured
instance. Only the username is removed, so a stored password keeps
working. Use 'agh-cli instance credentials password set <instance>' to
change the password without restoring a username.

### Usage

```bash
agh-cli instance credentials username clear <instance>
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
