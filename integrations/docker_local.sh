#!/usr/bin/env bash
# VKarmani local Docker ONLY. No user/root contexts, credentials or remote daemons.
set -Eeuo pipefail
set +x
umask 077
SOCKET=/var/run/docker.sock
if [[ ! -S "$SOCKET" || -L "$SOCKET" ]]; then
    echo 'LOCAL_DOCKER_UNAVAILABLE: expected Unix socket /var/run/docker.sock' >&2
    exit 1
fi
if [[ ! -x /usr/bin/docker ]]; then
    echo 'LOCAL_DOCKER_UNAVAILABLE: /usr/bin/docker not executable' >&2
    exit 1
fi
config=$(mktemp -d /tmp/vkarmani-docker-cli.XXXXXXXX) || exit 1
trap 'rm -rf -- "$config"' EXIT
# Empty isolated config prevents a saved remote Docker context, proxy or auth
# plugin from influencing local operations. No global context is changed.
env -i PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    HOME=/root DOCKER_CONFIG="$config" \
    /usr/bin/docker --host unix:///var/run/docker.sock "$@"
