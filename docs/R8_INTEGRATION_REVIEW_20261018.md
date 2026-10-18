# Node_Install 2.5.10 — review and scoped integration (2026-10-18)

**INCOMPLETE_STAGING_ONLY.** No installation on a real VPS, Remnawave Panel or live clients was performed.

## Source

- GitHub baseline `main`, commit `d7154b0095a28e8bc9e5fa5ebdc917b2090aeb8a` (r7f).
- User-provided complete r8 ZIP, verified SHA256 `6a2b086a07f21b7dfae1a519b0a94dd5f4780f4f2f1f68b44462916099499de5`.
- Reviewed all 13 r8 modified files; no removed baseline files.

## Imported from r8

1. Removal of duplicate Docker `--host` in finalization and its embedded copy.
2. Content-addressed CSS for six site variants and backward-compatible journal rollback.
3. Ordinary RAW profile additions: bittorrent, geosite:private and outbound finalRules.
4. All accompanying tests and documentation, preserving the original project modules.

## Additional repairs in this candidate

- R7 `owned-installation` gate accepts the zero-byte `touch` marker created by the installer; ownership/type/permission and other version/complete checks remain active.
- Legacy `--update-cover`/`--rollback-cover` refuse to run while an R7 site receipt is pending/active, avoiding cross-mechanism changes to `index.html`.
- On **ordinary** nodes only, final REALITY export also creates root-private `/root/vkarmani-raw-profile.json`, a byte-exact copy of the generated Config Profile, verified again by the finalizer before installation completion. It is **not** a live Xray config. Existing foreign or modified export files are not overwritten. Cascade profiles are not duplicated.

## Eight follow-up requests from the quoted AI chat — actual status

1. Mandatory reboot after install: default auto reboot already exists. **Keep `--no-reboot` as an essential explicit safety / staging escape hatch.** No forced reboot on partial failure or `--finish-install`.
2. Daily 03:00–03:59 Moscow randomized Docker maintenance: already implemented (ordinary only). Preserve at-most-once and not-running skip.
3. Weekly reboot: existing opt-in `--weekly-reboot`, fixed Monday 04:00; requested random default was **not** switched on. Automatic host reboot without peer coordination is disruptive; requires a dedicated safe rollout/acceptance decision, prohibited for cascade.
4. Two `/root` files for ordinary: implemented `/root/reality-keys.txt` and `/root/vkarmani-raw-profile.json` (root:0600).
5. One-vCPU/1 GiB Ubuntu 26.04: **not lowered** the 1536 MiB gate without full 1-GiB RAM/Swap+load soak; Ubuntu 22.04/24.04 already require >=900 MiB. No arbitrary kernel tuning.
6. nginx.org mainline repository: **not silently substituted** for the distribution source; switching package vendor affects Nginx stream modules, Certbot, on-disk config and rollback, and needs OS-specific VPS testing. Official site documents 22.04/24.04/26.04 support; candidate retains existing signed OS packages.
7. Password SSH/root: existing policy retained; do not add an unexpected forced TCP/22 migration, existing SSH ports are deliberately preserved.
8. IPv6 disabling: existing GRUB, sysctl, Docker and postboot checks retained; live verification requires a VPS reboot.

## Acceptance and rollback

Use an isolated snapshot-backed staging VPS; verify `sha256sum -c SHA256SUMS`, `scripts/verify_release.py`, full tests, actual install/finish, SSH reentry, APT, Docker, TLS, and Panel/live client flows. Before changing nginx package vendor or adding automatic weekly reboot, test migration and rollback on all supported OS releases. Rollback of this candidate is restoration of the VPS snapshot, not simply running an old installer over a completed new installation.
