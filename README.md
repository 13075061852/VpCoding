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
3. **Probe REALITY destinations with a real handshake** and deploy the first one that works, so a target that is unreachable or incompatible with the installed Xray release can never be written into the config.
4. Generate a fresh Reality keypair, initial Xray configuration and self-signed panel certificate.
5. Create the config directory with the correct ownership (`root:xray-att-relay`, mode `2750`) so the unprivileged Xray service can actually read `config.json`, and keep it readable after the panel rewrites it.
6. Generate a random administrator password and save it in `/root/relay-admin-credentials.txt` (`0600`).
7. Enable and start `xray-att-relay.service` and `node-admin.service`, then require **both** to be active, with TCP `8443` and `8444` actually listening and the panel health endpoint returning `ok`.
8. Run `selftest.sh`: inject a temporary client, complete a **real REALITY handshake** against the live service, fetch a URL through the tunnel, and restore the zero-state config. The installer only reports success after this passes.

### Choosing the REALITY destination

The default candidate list is `www.bing.com:443`, `www.cloudflare.com:443`, `www.amazon.com:443`, `www.apple.com:443`, probed in order. Pin one explicitly when needed:

```bash
sudo bash install.sh --host YOUR_HOST --dest www.bing.com:443
```

Avoid targets with very large certificate chains (for example `www.microsoft.com:443`), which have been reported to break REALITY handshakes in recent Xray releases. Xray also warns that apple/icloud targets risk getting the relay IP blocked by the GFW, so those are only used as a last resort.

Open TCP **8443** and **8444** in the cloud-provider firewall/security group. The first browser visit warns about the self-signed panel certificate; this is expected. Change the panel password after the first login, then securely delete `/root/relay-admin-credentials.txt`.

## Verifying an installation

`selftest.sh` is a standalone verification tool:

```bash
sudo bash selftest.sh                 # full check, including a real handshake
sudo bash selftest.sh --quick         # services, ports and panel health only
sudo bash selftest.sh --probe-dest www.apple.com:443   # probe one REALITY target
```

Full check output looks like:

```
Relay Control self-test
  [ok]   xray-att-relay active
  [ok]   node-admin active
  [ok]   TCP 8443 listening
  [ok]   TCP 8444 listening
  [ok]   panel health endpoint https://127.0.0.1:8444/healthz
  [ok]   REALITY handshake and proxied request through TCP 8443 (SNI www.apple.com)
  [ok]   zero-state config restored and entry port listening
Self-test passed.
```

The full check temporarily adds a client named `__selftest__` to the live config, restarts Xray, tests, then restores the previous config — even if the test fails. It never leaves the temporary client behind.

## Updating an existing installation

`install.sh` intentionally refuses to overwrite an existing installation. To update only the panel files while preserving Xray configuration, clients, relay state, certificates, credentials, and ports:

```bash
cd relay-control
git pull --ff-only
sudo bash update.sh
```

`update.sh` creates a local application backup, rolls back automatically if the panel health check fails, and runs `selftest.sh --quick`. It does **not** restart Xray.

## What the zero-state configuration contains

The installed Xray configuration has a VLESS Reality inbound, `direct` and `block` outbounds, and **no clients, upstream nodes, subscriptions, or forwarding rules**. Use the panel to add upstream nodes and create forwarding credentials. Do not paste production `/etc/node-admin` or `/etc/xray-att-relay` into this repository.

## Security notes

- The panel uses HTTPS, CSRF tokens, secure cookies, password hashing, login rate limits, and file permissions.
- `/etc/xray-att-relay` is `root:xray-att-relay` mode `2750` with a `0640` config. The setgid bit keeps the group on files the panel rewrites, so the Xray service keeps read access.
- The default panel certificate is self-signed. Put a managed TLS reverse proxy in front of TCP 8444 if public browser access requires a trusted certificate.
- Restrict TCP 8444 to trusted administrator IPs at the provider firewall when possible.
- Backups created in the panel remain on the server because they can contain sensitive configuration.
- This repository pins an Xray version in `install.sh`; review and update it deliberately.

## Repository hygiene

Run locally before publishing:

```bash
bash -n install.sh update.sh selftest.sh
python3 -m py_compile relay_admin/app.py relay_admin/operations.py
```

The GitHub workflow performs these checks and rejects obvious private configuration artifacts.
