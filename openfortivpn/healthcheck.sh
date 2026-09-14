#!/bin/sh
#
# Healthcheck: the container is healthy when a ppp interface is up with an
# IPv4 address. If HEALTHCHECK_TARGET is set, it must also be reachable.
#
set -u

iface="$(ip -o link show 2>/dev/null | awk -F': ' '$2 ~ /^ppp/ {print $2; exit}')"
if [ -z "$iface" ]; then
    echo "unhealthy: no ppp interface"
    exit 1
fi

if ! ip -4 addr show "$iface" 2>/dev/null | grep -q 'inet '; then
    echo "unhealthy: $iface has no IPv4 address"
    exit 1
fi

target="${HEALTHCHECK_TARGET:-}"
if [ -n "$target" ]; then
    if ! ping -I "$iface" -c1 -W3 "$target" >/dev/null 2>&1; then
        echo "unhealthy: cannot reach $target through the tunnel"
        exit 1
    fi
fi

echo "healthy: tunnel up on $iface"
exit 0
