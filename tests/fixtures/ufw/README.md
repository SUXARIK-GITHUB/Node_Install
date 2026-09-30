# UFW preflight regression fixtures

`ubuntu-24.04-0.36.2-6/user.rules` and `user6.rules` reproduce, line for line,
the files supplied in the operator's incident diagnostic output on 2026-09-30.
The reported OS was Ubuntu 24.04.4 and UFW was 0.36.2-6; UFW was inactive,
`ufw show added` reported `(None)`, and nftables/iptables dumps were empty.

These are copies of the reported files, **not a downloaded distro package**.
No credentials, addresses or hostname are stored in these fixtures.
The tests do not install UFW, apply rules or modify `/etc/ufw`.
IPv6 files are read as text; their validation does not enable IPv6.
