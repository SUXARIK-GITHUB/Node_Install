# Survivability / anti-abuse / observability — 2.5.0

The goal is a node that is easier to keep healthy, diagnose and replace without inventing censorship bypasses. It is not a promise that an IP is ban-proof, undetectable, reachable from every ISP or immune to provider action.

## Evidence quality

Production decisions use an explicit evidence hierarchy. Tier A is authoritative project/upstream evidence: current Node_Install source/tests/canary plus official Remnawave, Xray, Linux/Ubuntu, Docker, Nginx and systemd documentation/releases. Tier B is reproducible diagnostic/research methodology (for example layered DNS/TCP/TLS/control-vantage tools). Tier C is community observation/hypothesis. Tier C may define a scenario worth reproducing, but it must not become a hardcoded production default without independent confirmation.

As reviewed on 2026-10-06, the latest stable Remnawave Node release is 3.4.1 and the reviewed image source pins Xray v26.7.28. These are a dated upstream snapshot, not eternal constants; release work must re-check them.

## Public TCP surface

The fresh/current-node reviewed public IPv4 TCP surface is:

- saved SSH ports owned by `sshd`;
- `PUBLIC_IP:80` owned by Nginx for ACME/redirect;
- `PUBLIC_IP:443` owned by `rw-core`/Xray when the profile is live;
- `NODE_PORT` (normally 2222) owned by RemnaNode; UFW still restricts its source to the Panel backend IPv4.

Loopback-only TCP listeners are ignored. An unexpected non-loopback TCP port is a failure. Missing/ambiguous PID/process ownership is not silently passed. The audit reports local port numbers only and does not inventory client/peer addresses. Unknown UDP listeners are not universally hard-failed because provider DHCP/time/network images differ; no diagnostic UDP service is added.

## Resource diagnostics

The existing `sudo bash install.sh --diagnose-resources` remains a one-shot read-only helper; there is no daemon, timer or scanner. 2.5.0 adds:

- `nf_conntrack_count` / `nf_conntrack_max`, host-wide scope;
- total/available root filesystem MiB and available percent using `statvfs.f_bavail`;
- total/available inodes and available percent using `f_favail`;
- read-only distro `reboot-required` marker;
- status hints for daemon FD usage and container OOM state.

Diagnostic thresholds:

- conntrack: WARN `>=70%`, CRITICAL `>=85%`;
- daemon FD soft limit: WARN `>=70%`, CRITICAL `>=85%`;
- free inodes: WARN `<10%`, CRITICAL `<5%`;
- root free: WARN `<10%` or `<1 GiB`; CRITICAL `<5%` or `<512 MiB`;
- `OOMKilled=true`: CRITICAL.

These are observations, not auto-tuning triggers. The helper never changes MTU, offload, qdisc, TCP buffers, BBR, `nf_conntrack_max`, process limits, swap, Docker memory limits or firewall state. MemAvailable/swap/PSI are exposed as facts without a universal hard-fail threshold.

## Anti-abuse boundaries

Use the documented Panel Node Plugins baseline to reduce obvious SMTP/SMB abuse risk and support torrent/connection-drop controls. Do not duplicate Node Plugin policy into a second host firewall manager. There is no source-IP rate-limit on public 443 because legitimate users may share NAT. There are no automatically downloaded third-party IP lists.

Provider abuse/suspension and censorship/path failure are separate incident classes. Preserve evidence and console/snapshot access before destructive action. A compromised root invalidates trust in local checker output; rebuild a clean VPS and rotate affected credentials rather than trying to certify the compromised machine.

## Privacy/redaction

Diagnostics must not expose `SECRET_KEY`, REALITY/TLS private keys, full container environment, user UUID/email/subscription links, client/remote IP lists, raw socket FD targets, cookies/Authorization headers or default full PCAP. Aggregated host counters, own public node IP/domain, local ports and process/PID ownership evidence are acceptable where needed.
