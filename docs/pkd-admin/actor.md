# pkd-admin actor

The `actor` command is used to manage actors in the Public Key Directory (PKD) server.

**Usage**:

`pkd-admin actor [subcommand]`

## Sub-commands

- `crypto-shred`: Crypto-shred an actor's data

### crypto-shred

The `crypto-shred` command crypto-shreds an actor's data, rendering it unrecoverable.

**Usage**:

`pkd-admin actor crypto-shred [actor-id] [flags]`

**Arguments**:

- `actor-id`: The ID of the actor to crypto-shred.

**Flags**:

- `--config`: config file (default is ./config.yaml)
- `--help`: help for crypto-shred
