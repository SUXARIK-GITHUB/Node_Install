# Node_Install 2.5.10 r6 — Cascade operational gates and remaining work

**Date:** 2026-10-15 · **Status:** `INCOMPLETE_STAGING_ONLY / NOT_PRODUCTION_VALIDATED / NOT_PUBLISHED`.  
**Scope:** dedicated **new** Entry + Exit staging VPS, not installed production nodes or the Panel/technical server. All helpers below are READ-ONLY or create only explicitly named NEW local backup/output files. They never mutate the Remnawave Panel, SSH/UFW, Nginx, Docker, clients, or the database by themselves. Original `install.sh` still performs host modifications when deliberately invoked for a new installation.

## Precisely what r6 adds

1. `integrations/cascade_panel_inventory.py`: strict offline gate checking the normalized *v3* Remnawave objects. It binds exactly two independent Nodes and profiles, active inbound tags, separate client/bridge squads, **one public Host only on Entry** and **one `ACTIVE` bridge user with its `vlessUuid` matching the immutable pair bundle**. User ID (`id` in v3) is not a VLESS UUID. A plain JSON export or hand-entered snapshot does not prove the panel is really configured; the evidence must be captured by an authorized operator from a separate test panel. No API write is implemented.
2. `integrations/cascade_live_gate.py`: `--live-cold` retrieves **cold** Xray JSON via read-only `/usr/local/sbin/vkarmani-docker-local exec remnanode cli --dump-config` and validates the complete supplied JSON with `cascade_panel_audit.py`. Does not print user IDs, keys, or raw JSON. This is not proof of actual user connections, uptime or no DNS leakage. `--computed-json` supports safe fixture-based tests without Docker. Needs local root on the staging VPS for `--live-cold`.
3. `integrations/rkn_guard.py` **and the identical embedded `VK_RKN_GUARD_PY` in `install.sh`**: exit-only source exception for its *pinned* Entry peer IPv4 is included in the existing RKN trusted-source ipset, in addition to panel backend IPs. A matching root-private immutable `cascade-role.json` and role marker are mandatory; unexpected mode/symlink, invalid PairID, partial enrollment or modified peer **fail closed**. The Node API **UFW management port** still only permits `config.json.panel_ipv4` — the peer is not added to that management ACL. Ordinary and Entry nodes retain the previous RKN behaviour. Kernel systemd/ipset reconciliation after reboot is not locally proven.
4. `integrations/cascade_recovery.py` creates an **atomic, root-private limited config/role backup** to a new 0600 ZIP and verifies each member hash, role pair ID, state marker, domain/IP. It refuses symlinks, unexpectedly oversized files, mismatched state, tampering, output overwrites and incomplete snapshots. **It is not a complete VPS/DB/Docker/Panel backup.** Archive includes `SECRET_KEY` and private REALITY key; move to encrypted offline storage immediately. No automatic restore command to live `/etc` is exposed.
5. `tests/test_2510_r6_remaining_gates.py` exercises positive/negative scope checks, RKN role corruption, no-change ordinary policy, cold config comparison, backup tampering and output safety. Existing tests for ordinary routing and release integrity remain in place.

## Exact staging workflow — no example IP/credentials to paste blindly

1. Snapshot **both** brand-new VPS and TEST Remnawave Panel DB/config using the provider’s independently validated procedure. Verify out-of-band console access. Record OS/kernel, release ZIP SHA, panel build/version, Node image digest, public IPv4, FQDN and external reachability **without secrets**. Do not use live production infrastructure.
2. On a trusted Linux workspace, generate pair and prepare role bundles following `docs/CASCADE_R5_ROLE_INSTALL_AND_PANEL.md`. Transfer only `entry/role-bundle.json` to Entry and only `exit/role-bundle.json` to Exit, using a private authenticated transport. Never paste these files into a chat or logs.
3. Run Exit install before Entry: `sudo bash ./install.sh --cascade-role exit --cascade-bundle /root/exit/role-bundle.json --no-reboot` and the Entry variant with its own bundle. Both commands change their respective *new* test OS; require operator approval and provider snapshots first.
4. In a **separate TEST Panel** create distinct Nodes/profiles, client and bridge squads, one bridge service user with its **VLESS UUID explicitly equal to `service_user_uuid`**, and exactly one public Host for Entry. Test against the **actual panel version** and API schema first. Do not merge with existing real customer squads, profiles or hosts. The script does NOT create these objects for you; this remains an open automation requirement.
5. Capture a **normalized operator-only inventory** per contract below. Keep 0600; do not store raw user lists or API tokens in the project tree. Check it from a trusted offline workspace:

   ```bash
   umask 077
   python3 integrations/cascade_panel_inventory.py \
     --entry-bundle /root/pair/entry/role-bundle.json \
     --exit-bundle /root/pair/exit/role-bundle.json \
     --inventory /root/private/test-panel-inventory.json
   ```

6. On each staging VPS verify the cold config returned by RemnaNode CLI (without saving/printing secrets):

   ```bash
   sudo python3 integrations/cascade_live_gate.py \
     --role-bundle /etc/vkarmani-node/cascade-role.json --live-cold
   ```

   `CASCADE_COLD_AUDIT=PASS` is a **cold config check only**. Confirm separately that Xray is actually running and that the live configurations used for new connections match expectations. Never print computed JSON containing credentials to CI/public logs.
7. On Exit run ordinary safe `--rkn-status` read-only diagnostics on the script installed **on that exact server**, then verify its new trusted ipset actually contains BOTH panel IPs and the pinned Entry source address. The r6 source change only applies on new r6 installs: merely replacing an archive **does not update existing installed helpers**. Real UFW/IPSet/boot tests remain required.
8. Make a **limited local role-state backup**, then verify it, and transfer it only to separately encrypted storage:

   ```bash
   umask 077
   sudo python3 integrations/cascade_recovery.py create --source-root / \
       --output /root/cascade-local-state-unique.zip
   sudo python3 integrations/cascade_recovery.py verify \
       --backup /root/cascade-local-state-unique.zip
   ```

   Copying this file to an unencrypted shared location is unsafe. Provider VPS snapshots and Panel PostgreSQL backups are additional non-optional recovery assets.
9. From a separate test client and vantage point test RAW+REALITY, TCP/UDP, DNS, expected Exit egress IP, bridge UUID failure, RKN and UFW after reboot, ACME TLS and Selfsteal; intentionally stop Exit and verify **no fallback/direct user path from Entry** with packet capture. Test restarting Entry and Exit in both orders and do a *real* restore to **new staging machines**, never to production.
10. Complete `scripts/staging_acceptance.py` SHA-bound evidence checklist from real independent evidence. `ACCEPTED` requires **all** PASS with timestamps/operator and reference; the script does not verify evidence authenticity. External 24h soak, concurrency, monitoring alarms, CRON/systemd health, the subscription-routing technical server and client compatibility remain mandatory.

## Normalized Remnawave v3 inventory contract (NO actual identities)

Private JSON file with **exact keys**: `schema=1`, `panel_api_major=3`, `nodes`, `profiles`, `squads`, `hosts`, `users`. This is a *normalized operator statement*, **not** the undocumented assumption that all `GET /api/*` responses share this shape.

- `nodes`: exactly 2: each `{role:"entry"|"exit", uuid:"node-id", address:"this-role-FQDN-or-public-IPv4", port:2222, profile_uuid:"profile-id", active_inbounds:["its-own-inbound-tag"]}`. Actual ports must be used.
- `profiles`: exactly 2: each `{uuid:"profile-id", inbound_tags:["its-own-inbound-tag"]}`. Profiles must be distinct.
- `squads`: exactly 2: each `{purpose:"clients"|"bridge", uuid:"squad-id", inbound_tags:["exact-tag"]}`. Client tag is Entry only, bridge tag Exit only.
- `hosts`: exactly 1: `{inbound_tag:"entry-inbound-tag", node_uuid:"entry-node-id"}`. No public client Host for Exit.
- `users`: exactly 1: `{purpose:"bridge", vlessUuid:"actual-VLESS-credential-UUID", status:"ACTIVE", active_internal_squads:["bridge-squad-id"], expireAt:"future-RFC3339-time"}`. `vlessUuid` must match role bundle. Expires more than one day in the future.

This strict isolated inventory **does not attempt to audit an existing nonempty production Panel**: it intentionally fails if unrelated users/nodes/hosts are exported. Do not delete or move real users just to make this pass; use a separate test panel.

## Critical unclosed items — never report complete without proof

| Gate | Code status | Required live proof |
|---|---|---|
| Automatic Panel creation/reconciliation of Node/Profile/Host/Squad/service user | **NOT IMPLEMENTED**; read-only inventory consistency checker only | Version-pinned API, least-privileged token, idempotent create/read-after-write, full rollback without affecting other users; test Panel |
| Two clean staging VPS and real client route | Installer code already exists | Actual install, client, computed/live Xray, TCP+UDP+DNS, expected Exit IP |
| Real bridge peer allowed by RKN/UFW | Code updated for **r6 new installs** | Real kernel ipset/UFW after cold boot, source test from Entry, negative Node API ACL |
| External health check and staggered maintenance | Only no-uncoordinated-restart guard exists | Operator-approved safe health gating and remote canary under loss/reconnect |
| Key/UUID rotation and rolling pair replacement | **NOT IMPLEMENTED** for running nodes | Second safe staged channel and rollback, user reassignment, no unexpected interruption |
| Full bare-metal and Panel restore | **NOT IMPLEMENTED**; local state-only backup available | Independent complete provider snapshots + PostgreSQL dump/restore in separate isolated staging |
| Nginx TCP stream/site deploy | Offline generator and six static sites exist | `nginx -t`, module capability, listener ownership, HTTPS, rollback on real VPS |
| Final production release | **NOT APPROVED** | All acceptance evidence + independently verified GitHub CI on exact commit/digest |

## Warning: do not try to migrate a working production node via the staging installer

Running `install.sh --cascade-role` on a VPS already carrying customer inbounds, another cascade, a panel or an existing reverse-proxy is explicitly out of scope and may interrupt service or fail preflight. An RKN source-code change in the ZIP is *not* an in-place update of already installed `/usr/local/lib/vkarmani-node/rkn_guard.py`. Any future migration needs a read-only inventory of actual state, verified full backups, canary on parallel infrastructure, and explicit rollback decision. No `curl | bash`, arbitrary admin token, or hidden API/DB edits are introduced by r6.

### Official API references and relevant compatibility note

- https://docs.rw/api/ — Remnawave 3.x API, fields `vlessUuid` for user (distinct from user numeric `id`).
- https://docs.rw/learn-en/server-routing/ — bridge user, Internal Squad and routing, *demonstration not production ready*.
- https://docs.rw/features/rescue-cli/ — `remnanode cli --dump-config` cold config.
- https://docs.rw/learn-en/config-profiles/ and https://docs.rw/learn-en/squads/ — profile/inbound/squad/host relations.
- https://github.com/Flecksis/rkn-guard and https://github.com/shadow-netlab/traffic-guard-lists — inspect changes upstream before RKN data policy updates.
