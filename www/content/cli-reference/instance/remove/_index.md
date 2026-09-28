---
title: Remove
description: Remove an instance configuration. The stored credential of the instance is kept, so clear it before removing the instance with 'agh-cli instance credentials ...
type: docs
---

Remove an instance configuration. The stored credential of the
instance is kept, so clear it before removing the instance with 'agh-cli
instance credentials password clear <instance>'.

### Usage

```bash
agh-cli instance remove <instance>
```

### Global Options

| Flag | Short | Default | Type | Description |
|------|-------|---------|------|-------------|
| `--config` | `-c` | "" | string | Path to config file |
