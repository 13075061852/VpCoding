# Relay Console upgrade — 2026-09-05

## Deployment

- Application: `/opt/node-admin/app.py`
- Modules/assets: `operations.py`, `console.css`, `console.js`, `delete-dialog.js` (loaded at startup)
- Management service: `node-admin.service`, HTTPS 8444
- Proxy service: `xray-att-relay.service` (not restarted during this UI release)
- Upgrade archive: `/var/backups/node-admin/pre-upgrade-20260905-075408.tar.gz`
- Original application: `/var/backups/node-admin/app-pre-console-20260905.py`

## Changes

- Unified desktop visual system and responsive mobile inventory cards.
- Overview of nodes, forwards, last-test mean latency, upcoming expiry (Host Status only).
- Unified custom node/forward deletion dialog, dependency preflight, inline errors, duplicate-submit guard and unknown-result handling. Browser tests mock deletion APIs; no customer records are deleted during tests.
- Search, status/expiry filters, sort, remembered page sizes and bounded visible pagination.
- CSV export of filtered metadata, excluding connection credentials and subscription URLs; formula injection escaping.
- Server-side private backups, retaining ten manual archives. Pre-upgrade archives are preserved.
- Allowlisted administrative audit log with rotation; no credentials/request bodies logged.
- Revoke other login sessions; password change also revokes other sessions.
- Authenticated JSON APIs return 401 instead of login HTML; mutation errors return failure.
- Restore missing flash/error messages; permit same-origin QR images in CSP.
- Bound socket read and browser request timeouts; no automatic mutation retry.
- New forwards default to expiry in 30 days; reject past/today expiry to prevent immediate shutdown.
- Reduced-motion support, keyboard focus, accessible dialogs and Ctrl/Cmd+K search.

## Operations

Host Status → Security and Maintenance contains backup, session and audit controls.
Backups stay on-server because they include secrets. Files have mode 0600.
Audit log: `/var/log/node-admin/audit.jsonl`, rotated at 2 MiB with one previous file.
A server backup restores configurations and application files, not the entire operating system.
Restore intentionally requires SSH; no dangerous one-click production restore is exposed.

## Roll back only this application release

```sh
install -m 0640 /var/backups/node-admin/app-pre-console-20260905.py /opt/node-admin/app.py.rollback
mv /opt/node-admin/app.py.rollback /opt/node-admin/app.py
systemctl restart node-admin
curl -fk https://127.0.0.1:8444/healthz
```

Do not restore older state/configuration files over current traffic counters or new customer records unless specifically needed.

## Verification and scope

Nine unittest checks: request lengths, API auth, mutation error reporting, session revocation, backup permissions/retention, audit allowlist, HTML escaping/rendering, invalid quota values, expired creation dates.
Playwright with Edge: desktop 1440px, phone 390px, tablet 768px; search, sorting, persisted pagination, modal keyboard controls, CSV credential exclusion, QR loading, host API, CSRF, page overflow, no JS console errors.
No destructive create/delete/restart test is run against customers' real proxy configuration.
The existing proxy quota enforcement, protocol support, and subscription generation remain in place. Expired-forward renewal/reconstruction and automatic failover are not implemented in this release.
