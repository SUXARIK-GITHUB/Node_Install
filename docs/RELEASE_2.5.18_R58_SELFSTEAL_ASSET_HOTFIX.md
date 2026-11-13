# R58 staging hotfix: Selfsteal checker and rich-site asset URL compatibility

## Confirmed failure

`site_manager.py deploy --theme 97-design-museum` can successfully render, write,
and Nginx-activate the website, but it then raises
`SERVICE_CHECK_FAILED_VKARMANI_SELFSTEAL_CHECK`, with `SITE_ROLLBACK=PASS`.
The installed checker accepts `assets/style-<sha>.css` and
`assets/icon-<sha>.svg`, while the reviewed site publisher writes
`/assets/style-<sha>.css` and `/favicon.svg`. Its own strict asset parser
therefore raises `COVER_ASSET_REFERENCE_NOT_LOCAL_VERSIONED`.

## Scope of correction

The embedded checker accepts exactly one optional leading slash for hash-named
local CSS/icon assets. It accepts `/favicon.svg` or `favicon.svg` as a link to
the installer-owned favicon. The favicon continues to be independently checked
against its on-disk bytes and actual HTTPS response by the existing full
`check_web_contract`. The checker continues to reject external resources,
unversioned CSS, traversal, query strings, non-hash asset names and nonlocal
icons. No changes were made to TLS, Xray/REALITY, Docker, UFW, SSH, Nginx,
website content or routing policy.

## Existing installed staging node

This release changes the checker **embedded in the future installer**. It does
**not automatically change an already installed checker**. The reviewed
`scripts/selfsteal_checker_repair.py` provides a deliberately opt-in repair
restricted to the exact known legacy SHA-256 (and a strict new SHA-256), with
file ownership/mode checks, a shared installer lock, a root-only backup, an
atomic replacement, and an immediate full local Selfsteal postcheck. It restores
the original checker if the postcheck fails. An unknown or operator-modified
checker is rejected.

On staging ONLY, after the provider snapshot and verification of the entire
new source archive (`sha256sum`, `scripts/verify_release.py`) and after confirming
that the previous `site_manager` receipt is not pending:

```bash
# Runs no installer and never touches Nginx or Xray.
python3 -B scripts/selfsteal_checker_repair.py --check
# Expected on the reviewed legacy node: LEGACY_ASSET_CHECKER_REQUIRES_UPDATE

# Separate, explicitly approved staging change only:
python3 -B scripts/selfsteal_checker_repair.py --apply --confirm-staging
# Expected: CHECKER_REPAIR=UPDATED BACKUP=...

/usr/local/sbin/vkarmani-selfsteal-check
python3 -B scripts/site_manager.py status
# After independent validation of the backup and node state, deploy separately.
```

The site deployment must not be retried blindly after a failed transaction.
Inspect the receipt, process state, HTTPS responses, and full checker output.
Do not repeat the core installation or rotate credentials for this website
issue. Keep the backup for a verified rollback; a `--rollback BACKUP` mode exists
only for the exact saved legacy checker, and only after the managed site is
rolled back and the old checker can pass its original website checks.

## Tests and limitations

The new regression exercises the actual embedded checker on the actual rich-site
publisher's resulting HTML, verifies legacy relative paths, rejects unsafe
resources and tests updater abort/rollback behavior. No production server
changes have been performed by this source release. Local tests do not replace
a real VPS staging acceptance after applying the opt-in checker update.

**SSH:** password-only policy unchanged. **Staging status:** incomplete pending
real node publication and client checks.
