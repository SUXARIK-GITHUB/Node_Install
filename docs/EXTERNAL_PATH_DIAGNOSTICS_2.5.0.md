# External path diagnostics — 2.5.0

A destination VPS cannot prove reachability from Russia or identify a censorship mechanism by inspecting itself. Local health, Panel reachability and client-path reachability are separate layers.

## Failure taxonomy

Use the narrowest supported verdict, not the generic word “ban”:

```text
NODE_DOWN
LOCAL_CONFIG_BROKEN
PANEL_TO_NODE_BROKEN
PROVIDER_FIREWALL_OR_ACL
PROVIDER_ABUSE_SUSPENSION
DNS_FAILURE_OR_POISONING
TCP_IP_PATH_BLOCK
TCP_443_PATH_BLOCK
TLS_OR_SNI_INTERFERENCE
TCP_STREAM_BEHAVIORAL_BLOCK
TCP_16_20_SUSPECTED
UDP_PATH_BLOCK
MOBILE_WHITELIST_OR_DEFAULT_DENY
PREFIX_OR_ASN_PATH_RESTRICTION_SUSPECTED
REMOTE_SITE_FAILURE
UNKNOWN_PATH_FAILURE
```

Some verdicts are impossible to establish locally and must remain `NOT_VERIFIED`.

## External vantage method

When available, compare at least three independent contexts:

1. non-RU control path;
2. RU fixed ISP;
3. RU mobile ISP/segment.

For each node test the same layers, in order:

```text
DNS -> TCP/443 -> TLS/cover HTTPS -> authenticated VPN client -> sustained data transfer
```

Use control target(s). If the controls fail at the same time, record `INCONCLUSIVE`, not “node blocked”. Preserve a time series with timestamp, vantage class and PASS/FAIL per layer rather than relying on one anecdotal timeout.

An operator-triggered TCP16–20-style experiment may be performed only against an endpoint you control, as research. It is not a background healthcheck and is not grounds for changing Nginx, SNI, transport or firewall defaults.

## Invalid inferences

Do not infer RU reachability from `ss :443`, Panel reachability from local TLS, client reachability from Panel API, an IP block from one timeout, nationwide filtering from one ISP, a TUN signature from one client failure, or undetectability from a working cover site. UDP failure does not automatically prescribe TCP and vice versa.

No scanner container, public diagnostic endpoint, third-party mass scan, cron probe or unpinned research binary is installed on production nodes.

Store only safe aggregated evidence. Never put user UUIDs, subscriptions, private keys, cookies or raw full PCAP into a public evidence bundle. If packet capture is operationally required, handle it privately and minimize scope/retention.
