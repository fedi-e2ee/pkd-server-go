# Public Key Directory Server

## Introduction

This document is a user manual for the Public Key Directory (PKD) server, a reference implementation for the
[Public Key Directory specification](https://github.com/fedi-e2ee/public-key-directory-specification).
This guide is intended for Fediverse users who wish to deploy and operate their own PKD server.

## What is a Public Key Directory?

A Public Key Directory (PKD) is a server-side component that helps solve the key management problem for other projects
that intend to implement end-to-end encrypted (E2EE) communication in the Fediverse. The PKD provides a way to discover
and verify the public keys of other users, ensuring that you are communicating with the intended person and not an 
impostor.

## How it Works (Key Transparency)

The PKD server uses a concept called Key Transparency. All public key enrollments and revocations are published to an
append-only Merkle tree. This creates a verifiable and auditable log of all key-related events.

Additionally, PKD servers can be configured to routinely commit 
[checkpoints](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#checkpoint)
onto each other's histories, thereby allowing strong trust to form as an emergent property of federated key 
transparency, rather than a top-down, authority-driven approach.

## How to Deploy

This section will guide you through the process of deploying the PKD server.

### Prerequisites

Before you begin, you will need:

* A server with a public IP address.
* A domain name that points to your server's IP address.
* Go (Golang) installed on your server to build and run the PKD server.
* A relational database.
  * PostgreSQL is recommended, but we also test with SQLite.

### Secure Deployment with a Reverse Proxy

The PKD server is designed to be run behind a reverse proxy that handles TLS termination. This is the recommended
deployment method for production environments.

#### Using Caddy

Caddy is a modern, easy-to-use web server that automatically handles HTTPS.

1. Install Caddy on your server.
2. Create a `Caddyfile` with the following configuration, replacing `example.com` with your domain and
   `localhost:8080` with the address of your PKD server:

   ```
   example.com {
       reverse_proxy localhost:8080
   }
   ```
3. Run Caddy. It will automatically obtain and renew a TLS certificate for your domain.

#### Using nginx

nginx is a popular, high-performance web server.

1. Install nginx on your server.
2. Obtain a TLS certificate for your domain (e.g., using Let's Encrypt).
3. Configure nginx to act as a reverse proxy. Here is a sample configuration:

   ```nginx
   server {
       listen 80;
       server_name example.com;
       return 301 https://$host$request_uri;
   }

   server {
       listen 443 ssl;
       server_name example.com;

       ssl_certificate /path/to/your/certificate.pem;
       ssl_certificate_key /path/to/your/private-key.pem;

       location / {
           proxy_pass http://localhost:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

### Configuring the Server

The PKD server is configured using a YAML file. By default, it looks for a file named `config.yaml` in the current
directory, or in `/etc/pkd-server-go`. You can also specify a different path using the `--config` flag when running the
server.

Here is an example `config.yaml` file:

```yaml
server:
  host: "127.0.0.1"
  port: 8080
  key_file: "/etc/pkd-server-go/operator-key.pem"
  key_password: "your-password" # Optional, if the key is encrypted

database:
  driver: "postgres" # or "sqlite"
  dsn: "postgresql://user:password@localhost:5432/pkd?sslmode=disable"

# Example for SQLite:
# database:
#   driver: "sqlite"
#   dsn: "/var/lib/pkd-server-go/pkd.sqlite"

sigsum:
  url: "http://localhost:8081"
  public_key: "" # Optional, if you want to verify the SigSum log's signature

peers:
  "example-peer.com":
    public_key: "peer-public-key"
```

### Running the Server

Once you have configured the server, you can run it using the following command:

```shell
go build -o pkd-server ./server
./pkd-server
```

By default, the server will look for a `config.yaml` file in the current directory or in `/etc/pkd-server-go`.
You can also specify a different configuration file using the `--config` flag:

```shell
./pkd-server --config /path/to/your/config.yaml
```

### Provisioning Keys

The server needs two asymmetric keypairs.

1. **Signing Keypair**. This will be an Ed25519 secret key and corresponding public key, used to sign HTTP responses.
2. **Protocol Message Encryption Keypair**. End users can optionally use HPKE to encrypt entire Protocol Messages to
   provide confidentiality against honest-but-curious Fediverse instance administrators.

The server needs to be configured with a private key for signing messages and a private key for HPKE. You can generate
and provision these keys using the `pkd-admin` tool that is included with this server:

```shell
pkd-admin keygen --config /path/to/your/config.yaml
```

This will write the new keys directly to your configuration file. If the file does not exist, it will be created.

If keys already exist in the configuration file, the command will abort to prevent accidental overwrites. You can use
the `--force` flag to override this behavior:

```shell
pkd-admin keygen --config /path/to/your/config.yaml --force
```

### SigSum Integration

To ensure the integrity and auditability of the key directory, this server integrates with a SigSum transparency log.
All key-related events are published to the SigSum log, creating a verifiable and tamper-evident record.

The `sigsum.url` configuration option specifies the URL of the SigSum server to use. This can be a local instance or a
remote, trusted SigSum server.

### Administrative Actions

To perform an administrative action, you can use the `pkd-admin` command line tools that ships with the server. However,
this isn't always the most convenient method, so we also enable token-based authentication for remote administrative
features.

Minting tokens currently requires `pkd-admin` during the server deployment.

```terminal
pkd-admin token mint [flags]
```

(See [pkd-admin token](pkd-admin/token.md) for more information.)

This will return an access token and refresh token. 

(All tokens are [PASETO v4.local](https://github.com/paseto-standard/paseto-spec) tokens that use symmetric-key 
authenticated encryption.)

## Project Goals

The design of the PKD server is guided by two main principles: **Build for People** and **Security Over Legacy**.

### Goals

* **Enable Secure Communication:** The primary goal is to enable more people to communicate securely with each other.
* **User-Friendly Security:** The aim is to minimize the knowledge and effort required for users to use the system
  securely. This means meeting people where they already are, not trying to force different behaviors.
* **Privacy:** User privacy is valued, and only the minimum amount of information necessary is stored. A mechanism for
  data deletion is also provided. See: [Crypto-shredding](https://github.com/fedi-e2ee/public-key-directory-specification/blob/main/Specification.md#message-attribute-shreddability).
* **Transparency:** There is a commitment to clearly communicating errors and security incidents to users.

### Non-Goals

* **Legacy Compatibility:** Security or simplicity will not be compromised for the sake of compatibility with existing,
  but flawed, standards.
* **Manual Key Verification:** While a strong foundation for trust is provided, advanced key verification mechanisms
  (e.g., comparing key fingerprints) are out of scope for this project but can be built on top of it.

## License

This project is licensed under the [ISC License](../LICENSE).
