# Node_Install 2.5.2 — real-VPS listener acceptance hardening

## Scope

2.5.2 is a narrow acceptance/runtime-observability release on top of 2.5.1. It does not change the RAW+REALITY+Vision+Selfsteal architecture, public ports, UFW policy, Docker network mode, Panel objects or Xray transport. It incorporates two additional false-negative fixes that were reproduced and then resolved on a real Ubuntu 24.04.4 amd64 VPS on 2026-10-06.

## Real-VPS findings

### 1. Preboot RemnaNode API can be an AF_INET6 dual-stack listener

Before the first reboot, the host had runtime IPv6 disabled by sysctl but the kernel IPv6 stack was still present. RemnaNode `rw-node` owned exactly one wildcard `*:2222` listener visible through `ss -6`, while `ss -4` showed no 2222 entry. `net.ipv6.bindv6only=0`, and direct IPv4 TCP connections to both `127.0.0.1:2222` and the node public IPv4 succeeded.

2.5.1 incorrectly treated the absence from `ss -4` as `MISSING_EXPECTED_PORTS=2222`.

2.5.2 accepts this state only when all of the following are proven:

- the only missing expected IPv4 listener is `NODE_PORT`;
- exactly one IPv6 wildcard listener exists on that port;
- its process is `rw-node`/`node` and PID belongs to the running `remnanode` container;
- `net.ipv6.bindv6only=0`;
- real IPv4 TCP connect succeeds to both loopback and the configured public IPv4.

No other missing listener is hidden by this exception. After the reboot with `ipv6.disable=1`, the same real node exposed `0.0.0.0:2222` normally through `ss -4`, so the exception was no longer needed.

### 2. Xray TCP/443 wildcard bind is a reviewed profile state

After reboot and live profile activation, the real node had:

- Nginx TCP/80 on the concrete node public IPv4;
- `rw-core` TCP/443 on `0.0.0.0:443`;
- `rw-node` TCP/2222 on `0.0.0.0:2222`;
- SSH on `0.0.0.0:22`.

The generated VLESS profile itself explicitly uses `listen: 0.0.0.0` on port 443, and the profile validator already permits that reviewed state. 2.5.1 listener acceptance nevertheless required 443 to bind to the concrete public IPv4 and produced `BIND_ADDRESS_MISMATCH PORTS=443` while the independent Xray ownership check passed.

2.5.2 aligns the listener audit with the generated profile contract:

- TCP/80 must still bind to the concrete public IPv4;
- TCP/443 may bind to either the concrete public IPv4 or `0.0.0.0`;
- the 443 process/PID must still be `rw-core`/`xray` owned by `remnanode`;
- arbitrary wildcard listeners and unexpected public ports remain failures.

## Canary result

The repaired real VPS then passed:

- kernel-level IPv6 disable after reboot (`ipv6.disable=1`, no `/proc/net/if_inet6`, no IPv6 addresses/routes);
- Docker/container/service checks;
- local Node TLS on loopback and public IPv4;
- exact NET_ADMIN / NET_RAW drop / no-new-privileges checks;
- Xray functional and security floors;
- RemnaNode nft runtime structure;
- public TCP listener policy;
- Xray 443 ownership and Selfsteal checks;
- full manual local acceptance;
- rerun of `vkarmani-node-postboot.service` with `Result=success`, `ExecMainStatus=0`;
- zero failed systemd units.

This proves the local host/container/reboot acceptance path. It does **not** prove Panel-to-node reachability, Panel Plugin Config assignment, authenticated client traffic, torrent detection or regional reachability. Those remain separate operator/canary checks.

## Security boundary

No firewall rule, Xray config, Docker capability, service or public port is loosened by this release. The dual-stack exception is proof-based and limited to `NODE_PORT`; the 443 wildcard allowance is limited to the reviewed Xray port and still requires process/container ownership.
