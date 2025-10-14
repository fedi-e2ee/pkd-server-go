# pkd-admin token

The `token` command is used to manage authentication tokens for the Public Key Directory (PKD) server.

**Usage**:

`pkd-admin token [command]`

## Sub-commands

- `mint`: Mint a new token pair

### mint

The `mint` command mints a new token pair (access and refresh tokens).

**Usage**:

`pkd-admin token mint [flags]`

**Flags**:

- `--config`: config file (default is ./config.yaml)
- `--key-file`: path to the key file (default is pkd-server.key)
- `--password`: password for the key file
- `--help`: help for mint
