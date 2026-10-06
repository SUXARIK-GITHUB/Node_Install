# Acceptance hotfix — 2.5.1

## Scope

`2.5.1` is a narrow patch release for two false-negative acceptance regressions first exposed by a real Ubuntu 24.04.4 / Docker Engine 29.8.2 installation of `2.5.0` on 2026-10-06. The node installation reached the final preboot acceptance stage: RemnaNode was running, local Node TLS and Selfsteal checks passed, Xray functional/security floors passed, and `table ip remnanode` passed. The installer then stopped before `INSTALL_COMPLETE` and before scheduling reboot because two newly added 2.5.0 checks mis-parsed valid runtime state.

No transport, firewall, SSH, Panel, Xray profile, Nginx, ACME, Docker image, Node Plugin schema, public port or kernel-tuning policy is changed by this hotfix.

## Root cause 1 — Docker 29.8 capability canonicalization

The Compose contract is unchanged:

```yaml
cap_add:
  - NET_ADMIN
cap_drop:
  - NET_RAW
security_opt:
  - no-new-privileges:true
```

The 2.5.0 checker read effective runtime values through `docker inspect`, but compared the JSON arrays literally with `['NET_ADMIN']` and `['NET_RAW']`.

Docker 29.8 canonicalizes capability names returned through the Engine API/inspect to the `CAP_` form, so a correct runtime can be represented as:

```json
["CAP_NET_ADMIN"]
["CAP_NET_RAW"]
```

That is a representation change, not an effective-policy change. 2.5.1 normalizes a leading `CAP_` before the exact comparison. It still requires exactly one added capability (`NET_ADMIN`), exactly one dropped capability (`NET_RAW`), and an active `no-new-privileges` security option. Extra capabilities still fail.

## Root cause 2 — scoped IPv4 text in `ss`

The public listener audit uses `ss -H -4 -lntp`. On Ubuntu 24.04, iproute2/systemd-resolved can display a loopback socket using interface scope notation such as:

```text
127.0.0.53%lo:53
```

The 2.5.0 parser passed `127.0.0.53%lo` directly to `IPv4Address`, producing `INVALID_LOCAL_DATA` instead of recognizing and ignoring the loopback-only listener.

2.5.1 strips one validated `%interface` display suffix before IPv4 classification. This does not hide public listeners: a non-loopback scoped address is still evaluated normally and an unexpected public port still fails.

## Explicit repair for the known failed 2.5.0 state

Fresh 2.5.1 installs use the corrected checker from the start.

For the exact failed 2.5.0 state described above, 2.5.1 adds:

```bash
sudo bash install.sh --repair-acceptance
```

This operation is intentionally narrow. It is allowed only when all of the following are true:

- project-owned state exists;
- `install-version` is exactly `2.5.0`;
- `INSTALL_COMPLETE` is absent;
- `INSTALL_FAILED` is the known `rc=1 line=6412` final-preboot checkpoint from the reviewed 2.5.0 installer;
- installed `vkarmani-node-check`, `node_plugins.py` and `time_helper.py` match the exact reviewed 2.5.0 SHA256 values;
- no network rollback or image-update transaction is pending;
- RemnaNode is currently running;
- `/root/reality-keys.txt` does not already exist.

The repair then:

1. takes a private backup of the three acceptance files and verifies its manifest;
2. stages the 2.5.1 helper/checker files in the destination filesystems;
3. verifies Bash/Python syntax before activation;
4. atomically activates helpers first and checker last;
5. runs the corrected `vkarmani-node-check --preboot`;
6. exports `/root/reality-keys.txt` only after acceptance succeeds;
7. creates `INSTALL_COMPLETE` for the original `2.5.0` installation and a separate `ACCEPTANCE_REPAIR_2_5_1` receipt;
8. automatically restores the old acceptance files if any pre-commit post-check fails.

The repair intentionally **does not rewrite `install-version`**: the base installation remains `2.5.0`, with a separate 2.5.1 acceptance-repair receipt.

The repair does **not** run APT, change SSH/UFW/iptables/nftables, change GRUB/sysctl, restart/recreate Docker or RemnaNode, alter Nginx/ACME, regenerate REALITY keys, mutate Panel objects or schedule an automatic reboot.

After a successful repair, verify access to provider console and a second SSH session, then perform one normal reboot so the already-written IPv6 GRUB setting becomes active and the installed postboot acceptance service runs:

```bash
sudo reboot
```

After reconnecting:

```bash
sudo vkarmani-node-check --postboot
sudo systemctl status vkarmani-node-postboot.service --no-pager
```

After the Profile/Host/Node Plugins are assigned in Remnawave Panel, run the stricter runtime check:

```bash
sudo vkarmani-node-check --require-xray
```

## What this hotfix does not prove

A green local acceptance still does not prove Panel-to-node reachability, authenticated client VPN operation from a specific ISP/region, provider firewall behavior, or censorship/path availability. Those remain separate canary/external-path checks documented in the 2.5.0 operational runbooks.

`2.5.1` must not be called production-verified until the corrected code is exercised on a real VPS after this patch.
