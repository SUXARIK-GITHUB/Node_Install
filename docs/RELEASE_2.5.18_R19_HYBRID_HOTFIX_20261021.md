# Node_Install 2.5.18 r19 — Hybrid Selfsteal access hotfix

## Confirmed incident, 21 October 2026

Ordinary-node installation with `reality_mode=max.ru` stopped at `install.sh` after `nginx -t` and successful Let's Encrypt issuance:

```
SELFSTEAL_CHECK=FAIL SSLEOFError
INSTALL_FAILED rc=1 line=9679
```

On the affected host TCP/2222 did not listen and Docker had no `remnanode` container. The Remnawave panel correctly reported `ECONNREFUSED` because installation had not reached container creation.

## Root cause and minimal fix

Nginx master (root) binds both Unix sockets. Nginx `stream` workers (Ubuntu/Debian default `www-data`) must connect upstream to `cover.sock` using `proxy_pass`. Previous directory `/run/vkarmani-selfsteal` was `0750 root:root`, preventing path traversal and yielding `EACCES` and a TLS EOF. The default direct-local Selfsteal does not have this Nginx-worker-to-Nginx-worker connection, so old offline tests missed the error.

Now `/run/vkarmani-selfsteal` has `0750 root:www-data` on initial creation and through systemd-tmpfiles. Non-owner users are not allowed to create or replace socket paths. Installation fails with a specific diagnostic if unexpected owner/group/mode is observed. No change to the managed sockets themselves or root/container role.

## Recovery (staging only)

1. Preserve the failed-install log and diagnostic status; do not copy private env or TLS keys into public tickets.
2. Do NOT just open TCP/2222: no process is listening. Do NOT run `--finish-install` without its finalization checkpoint or remove `INSTALL_FAILED`.
3. Preferred: restore a **verified provider snapshot from before the r18 installation** (keep provider console available); after confirming a clean VPS, deploy 2.5.18 r19 and repeat the original installation, including MAX option.
4. Test own HTTPS cover TLS1.2/TLS1.3/HTTP1.1/H2, externally-visible SNI, ACME renewal path, then RemnaNode control API listening TCP/2222 only for panel IPv4.
5. Verify after reboot: `/run/vkarmani-selfsteal` is `root:www-data` mode `750`, both Unix sockets active, client Xray REALITY authentication and panel control work.

No migration of existing installation markers or credentials is implemented; the affected host must not be blindly reinstalled in place. If snapshot restoration is unavailable, use a separate reviewed recovery playbook after full host-state inspection.

## Offline checks and limitations

Checks: syntax, release integrity, version contracts, Nginx-worker directory permission regression; existing test suite on an unprivileged user. **Real Nginx Stream upstream/REALITY/XHTTP test on a VPS is still necessary before production.**

## Rollback

Use the provider's **verified pre-install snapshot** (not just a config file backup) because the installer already changed apt packages, SSH, GRUB, UFW and Nginx before failure. Confirm SSH and firewall policy with out-of-band console first. Do not remove or alter second/third/fourth IPv4 addresses or the default route.
