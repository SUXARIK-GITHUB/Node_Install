# Safe node replacement — 2.5.0

Replacement is the correct recovery path when a VPS/IP/prefix/provider path is genuinely unusable or the host is compromised. It is not an automatic censorship workaround.

1. Do not destroy the old node before diagnosis/evidence.
2. Preserve provider snapshot and console/recovery access if policy allows.
3. Confirm local health on the old node.
4. Compare external control/RU vantage evidence; keep `INCONCLUSIVE` when evidence is insufficient.
5. If replacement is justified, create a **new clean VPS** and run the normal installer. Do not clone unknown `/root`, writable Docker layers, cron, binaries or firewall state from a suspicious host.
6. Run fresh local acceptance. Assign Profile/Node Plugins manually in Panel; installer remains node-only.
7. Test one canary user: cover HTTPS, authenticated VPN and sustained transfer.
8. Only then switch production Host/Node mapping using the existing Panel runbook.
9. Keep the old node for a bounded rollback window if provider policy permits.
10. Retire it only after rollback is no longer required and evidence/credentials have been handled.

Provider/ASN diversity can reduce a single infrastructure failure domain, but it does not guarantee resistance to blocking. Do not build a list of “rare ASNs”, automate provider hopping or promise that diversity prevents censorship. Select providers for ToS, abuse handling, console/recovery, snapshots and network quality as well.

The 2.5.0 installer does not provide an in-place `--repair-acceptance` migration for completed 2.4.1–2.4.3 nodes. A safe atomic repair contract was not proven by an actual production-node canary here; ordinary rerun therefore remains diagnostic-only and does not silently replace installed helpers.
