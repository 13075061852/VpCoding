# Relay Control

Relay Control is a self-hosted management panel for an Xray relay. This repository contains **application code and a zero-to-one installer only**. It deliberately contains no server IPs, accounts, passwords, certificates, subscription tokens, forwarding records, or existing Xray configuration.

## Fresh-server install

Supported: Debian 12/13 or Ubuntu 22.04/24.04, amd64, root access. The installer creates a new Xray Reality inbound on TCP `8443` and an HTTPS panel on TCP `8444`.

### Recommended — clone then run

```bash
git clone https://github.com/OWNER/REPOSITORY.git relay-control
cd relay-control
sudo bash install.sh --host YOUR_PUBLIC_IP_OR_DOMAIN
```

### One command after publishing this repository

Replace both placeholders with your GitHub path:

```bash
curl -fsSL https://raw.githubusercontent.com/OWNER/REPOSITORY/main/install.sh | \
  sudo bash -s -- --repo https://github.com/OWNER/REPOSITORY.git --host YOUR_PUBLIC_IP_OR_DOMAIN
```

If `--host` is omitted, the installer tries to discover the public IPv4 address. Passing it explicitly is recommended, especially behind NAT or when using a domain.

The installer will:

1. Install Python, QR support, Xray and required system packages.
2. Verify the Xray GitHub-release SHA-256 digest before installing it.
3. Generate a fresh Reality keypair, initial Xray configuration and self-signed panel certificate.
4. Generate a random administrator password and save it in `/root/relay-admin-credentials.txt` (`0600`).
5. Enable and start `xray-att-relay.service` and `node-admin.service`.
6. Verify the local HTTPS health endpoint before reporting success.

Open TCP **8443** and **8444** in the cloud-provider firewall/security group. The first browser visit warns about the self-signed panel certificate; this is expected. Change the panel password after the first login, then securely delete `/root/relay-admin-credentials.txt`.

## Updating an existing installation

`install.sh` intentionally refuses to overwrite an existing installation. To update only the panel files while preserving Xray configuration, clients, relay state, certificates, credentials, and ports:

```bash
cd relay-control
git pull --ff-only
sudo bash update.sh
```

`update.sh` creates a local application backup and rolls back automatically if the panel health check fails. It does **not** restart Xray.

## What the zero-state configuration contains

The installed Xray configuration has a VLESS Reality inbound, `direct` and `block` outbounds, and **no clients, upstream nodes, subscriptions, or forwarding rules**. Use the panel to add upstream nodes and create forwarding credentials. Do not paste production `/etc/node-admin` or `/etc/xray-att-relay` into this repository.

## Security notes

- The panel uses HTTPS, CSRF tokens, secure cookies, password hashing, login rate limits, and file permissions.
- The default panel certificate is self-signed. Put a managed TLS reverse proxy in front of TCP 8444 if public browser access requires a trusted certificate.
- Restrict TCP 8444 to trusted administrator IPs at the provider firewall when possible.
- Backups created in the panel remain on the server because they can contain sensitive configuration.
- This repository pins an Xray version in `install.sh`; review and update it deliberately.

## Repository hygiene

Run locally before publishing:

```bash
bash -n install.sh update.sh
python3 -m py_compile relay_admin/app.py relay_admin/operations.py
```

The GitHub workflow performs these checks and rejects obvious private configuration artifacts.
