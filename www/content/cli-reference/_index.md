---
title: CLI Reference
type: docs
---

Complete command reference for agh-cli, organized by functional area.

## Client operations

Manage AdGuard Home clients including listing, adding, updating, and deleting.

| Command | Description |
|---------|-------------|
| [add](/cli-reference/client/add/) | Add a client |
| [delete](/cli-reference/client/delete/) | Delete a client |
| [list](/cli-reference/client/list/) | List clients |
| [update](/cli-reference/client/update/) | Update a client |


## Filtering operations

Manage AdGuard Home filtering configuration, rules, and filter URLs.

| Command | Description |
|---------|-------------|
| [add-url](/cli-reference/filtering/add-url/) | Add a filter URL |
| [config](/cli-reference/filtering/config/) | Update filtering configuration |
| [remove-url](/cli-reference/filtering/remove-url/) | Remove a filter URL |
| [status](/cli-reference/filtering/status/) | Get filtering status |


## Manage configured AdGuard Home instances

List, add, and remove AdGuard Home instance configurations, and manage the credentials those instances use.

| Command | Description |
|---------|-------------|
| [add](/cli-reference/instance/add/) | Add a new instance configuration |
| [credentials](/cli-reference/instance/credentials/) | Manage stored instance credentials |
| [list](/cli-reference/instance/list/) | List configured instances |
| [remove](/cli-reference/instance/remove/) | Remove an instance configuration |


## DNS rewrite rule operations

Create, read, update, and delete DNS rewrite rules on one or more AdGuard Home instances.

| Command | Description |
|---------|-------------|
| [add](/cli-reference/rewrite/add/) | Add a rewrite rule |
| [delete](/cli-reference/rewrite/delete/) | Delete a rewrite rule |
| [diff](/cli-reference/rewrite/diff/) | Compare rewrite rules between instances or against a file |
| [list](/cli-reference/rewrite/list/) | List rewrite rules |
| [settings](/cli-reference/rewrite/settings/) | Rewrite settings operations |
| [update](/cli-reference/rewrite/update/) | Update a rewrite rule |
| [wildcard](/cli-reference/rewrite/wildcard/) | Wildcard rewrite rule operations |


## Version

Print the application version, including commit SHA and build details.

| Command | Description |
|---------|-------------|
| [version](/cli-reference/version/) | Print the application version |


