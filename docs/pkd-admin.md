# pkd-admin

## Synopsis

`pkd-admin [command]`

## Description

`pkd-admin` is a command-line interface for administering the Public Key Directory (PKD) server.

## Common Flags

While `pkd-admin` does not have universal global flags that apply to all commands, some flags are common across several subcommands.

- `--config`: Specifies a custom configuration file (default is `./config.yaml`). This flag must be provided for the specific subcommand that supports it.

All commands also support the `--help` flag to show usage information.

## Commands

- [`actor`](pkd-admin/actor.md): Manage actors
- [`keygen`](pkd-admin/keygen.md): Generate server keys
- [`token`](pkd-admin/token.md): Manage authentication tokens
- `help`: Help about any command
