#!/bin/bash
#
# Entrypoint for the openfortivpn gateway container.
#
# It reads its configuration from environment variables, pins a route to the
# VPN gateway on the physical uplink, installs a killswitch firewall and then
# keeps an openfortivpn session alive (reconnecting forever).
#
set -uo pipefail
umask 077

log() { printf '%s [openfortivpn] %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$*"; }
warn() { log "WARN: $*"; }
die() {
    log "ERROR: $*"
    exit 1
}

is_on() {
    case "${1,,}" in
        on | 1 | yes | true) return 0 ;;
        *) return 1 ;;
    esac
}

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
VPN_HOST="${VPN_HOST:-}"
VPN_PORT="${VPN_PORT:-443}"
VPN_USER="${VPN_USER:-}"
VPN_PASSWORD="${VPN_PASSWORD:-}"
VPN_PASSWORD_FILE="${VPN_PASSWORD_FILE:-}"
VPN_OTP="${VPN_OTP:-}"
VPN_OTP_FILE="${VPN_OTP_FILE:-}"
VPN_REALM="${VPN_REALM:-}"
VPN_TRUSTED_CERT="${VPN_TRUSTED_CERT:-}"
VPN_CLIENT_CERT="${VPN_CLIENT_CERT:-}"
VPN_CLIENT_KEY="${VPN_CLIENT_KEY:-}"
VPN_CA_FILE="${VPN_CA_FILE:-}"
VPN_SNI="${VPN_SNI:-}"
VPN_SET_DNS="${VPN_SET_DNS:-0}"
VPN_PPPD_PEERDNS="${VPN_PPPD_PEERDNS:-0}"
VPN_HALF_INTERNET_ROUTES="${VPN_HALF_INTERNET_ROUTES:-0}"
VPN_INSECURE_SSL="${VPN_INSECURE_SSL:-0}"
VPN_MIN_TLS="${VPN_MIN_TLS:-}"
VPN_FULL_TUNNEL="${VPN_FULL_TUNNEL:-on}"
VPN_EXCLUDE_ROUTES="${VPN_EXCLUDE_ROUTES:-100.64.0.0/10}"
VPN_RECONNECT_DELAY="${VPN_RECONNECT_DELAY:-5}"
VPN_EXTRA_ARGS="${VPN_EXTRA_ARGS:-}"

FIREWALL_ENABLED="${FIREWALL_ENABLED:-on}"
LAN_IFACE="${LAN_IFACE:-}"
LAN_SUBNET="${LAN_SUBNET:-}"
DNS_SERVERS="${DNS_SERVERS:-}"

CONFIG_FILE="${CONFIG_FILE:-/etc/openfortivpn/config}"

STOPPING=0
VPN_PID=""
CONFIGURED_IFACE=""
UPLINK_DEV=""
UPLINK_GW=""
SERVER_IPS=""
IPT="iptables"
IP6T="ip6tables"
ORIGINAL_RESOLV_FILE="/run/openfortivpn-resolv.conf"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
# Turn a host name into a space separated list of IPv4 addresses.
resolve_ipv4() {
    local host="$1"
    if [[ "$host" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        printf '%s' "$host"
        return 0
    fi
    # Only "Address:" lines carry answers; the "Server:" line and the
    # resolver address (which includes a port) are filtered out.
    nslookup "$host" 2>/dev/null \
        | tr -d '\r' \
        | awk '$1 == "Address:" {print $2} $1 == "Address" {print $3}' \
        | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
        | sort -u \
        | paste -sd' ' -
}

detect_uplink() {
    local line
    line="$(ip -4 route show default 2>/dev/null | head -n1)"
    [ -z "$line" ] && return 1
    UPLINK_DEV="$(awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}' <<<"$line")"
    UPLINK_GW="$(awk '{for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}' <<<"$line")"
    [ -n "$UPLINK_DEV" ]
}

current_ppp_iface() {
    ip -o link show 2>/dev/null \
        | awk -F': ' '$2 ~ /^ppp/ {print $2; exit}'
}

iface_has_ipv4() {
    ip -4 addr show "$1" 2>/dev/null | grep -q 'inet '
}

select_iptables_backend() {
    # Docker installs its embedded-DNS NAT rules using one of the two xtables
    # backends. Use that same backend so we preserve and compose with them.
    if iptables -t nat -S DOCKER_OUTPUT >/dev/null 2>&1; then
        IPT="iptables"
        IP6T="ip6tables"
    elif command -v iptables-legacy >/dev/null 2>&1 \
        && iptables-legacy -t nat -S DOCKER_OUTPUT >/dev/null 2>&1; then
        IPT="iptables-legacy"
        IP6T="ip6tables-legacy"
    elif iptables -L -n >/dev/null 2>&1; then
        IPT="iptables"
        IP6T="ip6tables"
    elif command -v iptables-legacy >/dev/null 2>&1 \
        && iptables-legacy -L -n >/dev/null 2>&1; then
        IPT="iptables-legacy"
        IP6T="ip6tables-legacy"
    else
        die "no usable iptables backend; NET_ADMIN is required"
    fi
}

ensure_chain() {
    local table="$1" chain="$2"
    "$IPT" -t "$table" -N "$chain" 2>/dev/null \
        || "$IPT" -t "$table" -F "$chain" \
        || die "could not prepare $table/$chain"
}

ensure_jump() {
    local table="$1" parent="$2" child="$3"
    "$IPT" -t "$table" -C "$parent" -j "$child" >/dev/null 2>&1 \
        || "$IPT" -t "$table" -I "$parent" 1 -j "$child" \
        || die "could not attach $table/$child to $parent"
}

refresh_credentials() {
    if [ -n "$VPN_PASSWORD_FILE" ]; then
        [ -f "$VPN_PASSWORD_FILE" ] || die "secret file does not exist: $VPN_PASSWORD_FILE"
        [ -r "$VPN_PASSWORD_FILE" ] || die "secret file is not readable: $VPN_PASSWORD_FILE"
        VPN_PASSWORD="$(cat "$VPN_PASSWORD_FILE")" \
            || die "could not read $VPN_PASSWORD_FILE"
    fi
    if [ -n "$VPN_OTP_FILE" ]; then
        [ -f "$VPN_OTP_FILE" ] || die "secret file does not exist: $VPN_OTP_FILE"
        [ -r "$VPN_OTP_FILE" ] || die "secret file is not readable: $VPN_OTP_FILE"
        VPN_OTP="$(cat "$VPN_OTP_FILE")" \
            || die "could not read $VPN_OTP_FILE"
    fi
}

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
create_ppp_device() {
    [ -e /dev/ppp ] && return 0
    log "creating /dev/ppp device node"
    mknod /dev/ppp c 108 0 2>/dev/null \
        || warn "could not create /dev/ppp; pass --device=/dev/ppp or run privileged"
}

enable_forwarding() {
    log "enabling IPv4 forwarding"
    echo 1 >/proc/sys/net/ipv4/ip_forward 2>/dev/null \
        || warn "could not enable net.ipv4.ip_forward"
}

write_config() {
    mkdir -p "$(dirname "$CONFIG_FILE")" || die "could not create the config directory"
    {
        echo "# generated by the openfortivpn entrypoint"
        echo "host = $VPN_HOST"
        echo "port = $VPN_PORT"
        [ -n "$VPN_USER" ] && echo "username = $VPN_USER"
        [ -n "$VPN_PASSWORD" ] && echo "password = $VPN_PASSWORD"
        [ -n "$VPN_OTP" ] && echo "otp = $VPN_OTP"
        [ -n "$VPN_REALM" ] && echo "realm = $VPN_REALM"
        [ -n "$VPN_TRUSTED_CERT" ] && echo "trusted-cert = $VPN_TRUSTED_CERT"
        [ -n "$VPN_CLIENT_CERT" ] && echo "user-cert = $VPN_CLIENT_CERT"
        [ -n "$VPN_CLIENT_KEY" ] && echo "user-key = $VPN_CLIENT_KEY"
        [ -n "$VPN_CA_FILE" ] && echo "ca-file = $VPN_CA_FILE"
        [ -n "$VPN_SNI" ] && echo "sni = $VPN_SNI"
        [ -n "$VPN_MIN_TLS" ] && echo "min-tls = $VPN_MIN_TLS"
        echo "set-dns = $VPN_SET_DNS"
        echo "pppd-use-peerdns = $VPN_PPPD_PEERDNS"
        echo "half-internet-routes = $VPN_HALF_INTERNET_ROUTES"
        echo "insecure-ssl = $VPN_INSECURE_SSL"
        echo "persistent = 0"
    } >"$CONFIG_FILE" || die "could not write $CONFIG_FILE"
    chmod 600 "$CONFIG_FILE" || die "could not protect $CONFIG_FILE"
}

# Keep the route to the VPN gateway on the physical uplink, otherwise the
# default route pushed through ppp0 would blackhole our own control channel.
pin_server_routes() {
    SERVER_IPS="$(resolve_ipv4 "$VPN_HOST")"
    if [ -z "$SERVER_IPS" ]; then
        die "could not resolve $VPN_HOST to an IPv4 address"
    fi
    log "VPN gateway $VPN_HOST resolves to: $SERVER_IPS"
    local ip
    for ip in $SERVER_IPS; do
        if [ "$VPN_HOST" != "$ip" ]; then
            # Keep reconnects independent of physical-interface DNS after the
            # killswitch is installed.
            printf '%s\t%s # openfortivpn gateway\n' "$ip" "$VPN_HOST" >>/etc/hosts \
                || die "could not pin $VPN_HOST in /etc/hosts"
        fi
        if [ -n "$UPLINK_GW" ]; then
            ip route replace "$ip/32" via "$UPLINK_GW" dev "$UPLINK_DEV" 2>/dev/null \
                || die "could not pin route to $ip via $UPLINK_GW"
        else
            ip route replace "$ip/32" dev "$UPLINK_DEV" 2>/dev/null \
                || die "could not pin route to $ip on $UPLINK_DEV"
        fi
    done
}

setup_firewall() {
    log "installing killswitch firewall ($IPT)"
    # Only manage our own chains. In particular, Docker's embedded DNS relies
    # on DOCKER_OUTPUT/DOCKER_POSTROUTING rules in this namespace.
    ensure_chain filter OFV_OUTPUT
    ensure_chain filter OFV_FORWARD
    ensure_chain nat OFV_POSTROUTING
    ensure_chain mangle OFV_MANGLE_OUTPUT
    ensure_chain mangle OFV_MANGLE_FORWARD

    # Loopback and replies.
    $IPT -A OFV_OUTPUT -o lo -j ACCEPT || die "could not allow loopback traffic"
    $IPT -A OFV_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
        || die "could not allow established traffic"

    # All traffic that leaves through the tunnel is fine.
    $IPT -A OFV_OUTPUT -o ppp+ -j ACCEPT || die "could not allow tunnel traffic"

    # Control channel to the VPN gateway on the physical uplink.
    local ip
    for ip in $SERVER_IPS; do
        $IPT -A OFV_OUTPUT -o "$LAN_IFACE" -d "$ip" -p tcp --dport "$VPN_PORT" -j ACCEPT \
            || die "could not allow VPN control traffic to $ip"
    done

    # Docker's embedded resolver is reached over loopback and forwards queries
    # outside this namespace. Direct resolvers are intentionally unavailable
    # until the tunnel is up, preventing physical-interface DNS leaks.
    $IPT -A OFV_OUTPUT -j DROP || die "could not close the OUTPUT killswitch"

    # Forwarded traffic (when the container is used as a real gateway).
    $IPT -A OFV_FORWARD -i ppp+ -o "$LAN_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
        || die "could not allow established forwarded traffic"
    if [ -n "$LAN_SUBNET" ]; then
        $IPT -A OFV_FORWARD -s "$LAN_SUBNET" -o ppp+ -j ACCEPT \
            || die "could not allow forwarded tunnel traffic"
    else
        $IPT -A OFV_FORWARD -o ppp+ -j ACCEPT \
            || die "could not allow forwarded tunnel traffic"
    fi
    $IPT -A OFV_FORWARD -j DROP || die "could not close the FORWARD killswitch"

    # NAT and TCP MSS clamping so forwarded traffic survives the small PPP MTU.
    $IPT -t nat -A OFV_POSTROUTING -o ppp+ -j MASQUERADE \
        || die "could not enable tunnel masquerading"
    $IPT -t mangle -A OFV_MANGLE_FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu \
        || warn "forwarded TCP MSS clamping is unavailable"
    $IPT -t mangle -A OFV_MANGLE_OUTPUT -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu \
        || warn "local TCP MSS clamping is unavailable"

    ensure_jump filter OUTPUT OFV_OUTPUT
    ensure_jump filter FORWARD OFV_FORWARD
    ensure_jump nat POSTROUTING OFV_POSTROUTING
    ensure_jump mangle OUTPUT OFV_MANGLE_OUTPUT
    ensure_jump mangle FORWARD OFV_MANGLE_FORWARD

    setup_ipv6_firewall
}

setup_ipv6_firewall() {
    # PPP tunnels here are IPv4-only. If the container has IPv6, fail closed
    # rather than letting it bypass the IPv4 killswitch.
    [ -s /proc/net/if_inet6 ] || return 0
    command -v "$IP6T" >/dev/null 2>&1 || die "IPv6 is active but $IP6T is unavailable"
    "$IP6T" -N OFV6_OUTPUT 2>/dev/null || "$IP6T" -F OFV6_OUTPUT \
        || die "could not prepare the IPv6 OUTPUT killswitch"
    "$IP6T" -N OFV6_FORWARD 2>/dev/null || "$IP6T" -F OFV6_FORWARD \
        || die "could not prepare the IPv6 FORWARD killswitch"
    "$IP6T" -A OFV6_OUTPUT -o lo -j ACCEPT || die "could not allow IPv6 loopback"
    "$IP6T" -A OFV6_OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT \
        || die "could not allow established IPv6 traffic"
    "$IP6T" -A OFV6_OUTPUT -j DROP || die "could not close the IPv6 OUTPUT killswitch"
    "$IP6T" -A OFV6_FORWARD -j DROP || die "could not close the IPv6 FORWARD killswitch"
    "$IP6T" -C OUTPUT -j OFV6_OUTPUT >/dev/null 2>&1 \
        || "$IP6T" -I OUTPUT 1 -j OFV6_OUTPUT \
        || die "could not attach the IPv6 OUTPUT killswitch"
    "$IP6T" -C FORWARD -j OFV6_FORWARD >/dev/null 2>&1 \
        || "$IP6T" -I FORWARD 1 -j OFV6_FORWARD \
        || die "could not attach the IPv6 FORWARD killswitch"
}

# ---------------------------------------------------------------------------
# Tunnel lifecycle
# ---------------------------------------------------------------------------
# Keep listed subnets on the physical uplink even when the VPN pushes a
# default route (e.g. Tailscale's 100.64.0.0/10, which must never go through
# the tunnel or management access breaks). Runs after openfortivpn installs
# its routes so excludes win.
apply_exclude_routes() {
    local routes="${VPN_EXCLUDE_ROUTES//,/ }"
    local cidr
    [ -z "${routes// /}" ] && return 0
    for cidr in $routes; do
        if [ -n "$UPLINK_GW" ]; then
            if ip route replace "$cidr" via "$UPLINK_GW" dev "$UPLINK_DEV" 2>/dev/null; then
                log "excluded $cidr from tunnel via $UPLINK_DEV"
            else
                warn "could not exclude $cidr from tunnel"
            fi
        else
            if ip route replace "$cidr" dev "$UPLINK_DEV" 2>/dev/null; then
                log "excluded $cidr from tunnel via $UPLINK_DEV"
            else
                warn "could not exclude $cidr from tunnel"
            fi
        fi
    done
}

POLICY_TABLE="200"
POLICY_MARK="0x1"

# Replies to inbound connections (published ports reached from LAN,
# Tailscale, ...) must leave via the physical uplink even when the VPN owns
# the main-table default route. Without this, return traffic disappears into
# the tunnel and the service looks dead from outside while working locally.
# Mark inbound connections and route marked replies through a dedicated table
# holding the original default route. CONNMARK survives reconnects and table
# 200 is never touched by openfortivpn/pppd, so this is set up once.
# Unmarked (locally initiated) traffic keeps using the main table, i.e. the
# tunnel: no leak. Same idea as Gluetun's inbound policy table.
setup_policy_routing() {
    [ -n "$UPLINK_DEV" ] || {
        warn "skipping policy routing: no uplink device"
        return 0
    }
    if [ -n "$UPLINK_GW" ]; then
        ip route replace default via "$UPLINK_GW" dev "$UPLINK_DEV" table "$POLICY_TABLE" 2>/dev/null \
            || {
                warn "could not set policy table default route"
                return 0
            }
    else
        ip route replace default dev "$UPLINK_DEV" table "$POLICY_TABLE" 2>/dev/null \
            || {
                warn "could not set policy table default route"
                return 0
            }
    fi
    if ! ip rule show 2>/dev/null | grep -q "fwmark $POLICY_MARK.*lookup $POLICY_TABLE"; then
        ip rule add fwmark "$POLICY_MARK" table "$POLICY_TABLE" 2>/dev/null \
            || {
                warn "policy routing unavailable (ip rule failed)"
                return 0
            }
    fi
    "$IPT" -t mangle -N OFV_PREROUTING 2>/dev/null \
        || "$IPT" -t mangle -F OFV_PREROUTING 2>/dev/null \
        || {
            warn "could not prepare mangle/OFV_PREROUTING"
            return 0
        }
    "$IPT" -t mangle -C PREROUTING -j OFV_PREROUTING >/dev/null 2>&1 \
        || "$IPT" -t mangle -I PREROUTING 1 -j OFV_PREROUTING 2>/dev/null \
        || {
            warn "could not attach mangle PREROUTING chain"
            return 0
        }
    "$IPT" -t mangle -C OFV_PREROUTING -i "$UPLINK_DEV" -m conntrack --ctstate NEW -j CONNMARK --set-mark "$POLICY_MARK" >/dev/null 2>&1 \
        || "$IPT" -t mangle -A OFV_PREROUTING -i "$UPLINK_DEV" -m conntrack --ctstate NEW -j CONNMARK --set-mark "$POLICY_MARK" 2>/dev/null \
        || {
            warn "could not add inbound marking rule"
            return 0
        }
    "$IPT" -t mangle -N OFV_MARK_OUT 2>/dev/null \
        || "$IPT" -t mangle -F OFV_MARK_OUT 2>/dev/null \
        || {
            warn "could not prepare mangle/OFV_MARK_OUT"
            return 0
        }
    "$IPT" -t mangle -C OUTPUT -j OFV_MARK_OUT >/dev/null 2>&1 \
        || "$IPT" -t mangle -I OUTPUT 1 -j OFV_MARK_OUT 2>/dev/null \
        || {
            warn "could not attach mangle OUTPUT chain"
            return 0
        }
    "$IPT" -t mangle -C OFV_MARK_OUT -j CONNMARK --restore-mark >/dev/null 2>&1 \
        || "$IPT" -t mangle -A OFV_MARK_OUT -j CONNMARK --restore-mark 2>/dev/null \
        || {
            warn "could not add mark restore rule"
            return 0
        }
    log "policy routing ready: inbound replies via $UPLINK_DEV (table $POLICY_TABLE)"
}

on_tunnel_up() {
    local iface="$1"
    log "tunnel is up on $iface"
    if is_on "$VPN_FULL_TUNNEL"; then
        if ip route replace default dev "$iface" 2>/dev/null; then
            log "default route now points at $iface"
        else
            warn "could not set default route via $iface"
        fi
    fi
    apply_exclude_routes
    if [ -n "$DNS_SERVERS" ]; then
        { for ns in ${DNS_SERVERS//,/ }; do echo "nameserver $ns"; done; } >/etc/resolv.conf 2>/dev/null \
            || warn "could not write /etc/resolv.conf"
        log "using DNS servers: $DNS_SERVERS"
    fi
}

on_tunnel_down() {
    log "tunnel went down"
    # Restore the physical default route so DNS and the next reconnect attempt
    # keep working. The killswitch still blocks everything else.
    if [ -n "$UPLINK_DEV" ]; then
        if [ -n "$UPLINK_GW" ]; then
            ip route replace default via "$UPLINK_GW" dev "$UPLINK_DEV" 2>/dev/null \
                || warn "could not restore the physical default route"
        else
            ip route replace default dev "$UPLINK_DEV" 2>/dev/null \
                || warn "could not restore the physical default route"
        fi
    fi
    if [ -n "$DNS_SERVERS" ] && [ -f "$ORIGINAL_RESOLV_FILE" ]; then
        cp "$ORIGINAL_RESOLV_FILE" /etc/resolv.conf 2>/dev/null \
            || warn "could not restore /etc/resolv.conf"
    fi
}

monitor_tunnel() {
    local pid="$1" iface
    while kill -0 "$pid" 2>/dev/null; do
        iface="$(current_ppp_iface)"
        if [ -n "$iface" ] && iface_has_ipv4 "$iface"; then
            if [ "$CONFIGURED_IFACE" != "$iface" ]; then
                CONFIGURED_IFACE="$iface"
                on_tunnel_up "$iface"
            fi
        elif [ -n "$CONFIGURED_IFACE" ]; then
            CONFIGURED_IFACE=""
            on_tunnel_down
        fi
        sleep 2
    done
}

run_once() {
    local args=(-c "$CONFIG_FILE")
    local rc
    refresh_credentials
    write_config
    if [ -n "$VPN_EXTRA_ARGS" ]; then
        local extra
        read -r -a extra <<<"$VPN_EXTRA_ARGS"
        args+=("${extra[@]}")
    fi
    log "connecting to $VPN_HOST:$VPN_PORT as ${VPN_USER:-<no user>}"
    openfortivpn "${args[@]}" &
    VPN_PID=$!
    monitor_tunnel "$VPN_PID"
    wait "$VPN_PID"
    rc=$?
    VPN_PID=""
    on_tunnel_down
    CONFIGURED_IFACE=""
    return "$rc"
}

shutdown() {
    [ "$STOPPING" = 1 ] && return
    STOPPING=1
    log "shutting down"
    if [ -n "$VPN_PID" ]; then
        kill "$VPN_PID" 2>/dev/null
        wait "$VPN_PID" 2>/dev/null
    fi
    on_tunnel_down
    exit 0
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
[ "$(id -u)" = 0 ] || die "this container must run as root"

# Allow the image to be used as a normal base image too.
if [ "$#" -gt 0 ]; then
    exec "$@"
fi

[ -n "$VPN_HOST" ] || die "VPN_HOST is required"
if ! [[ "$VPN_PORT" =~ ^[0-9]+$ ]] \
    || ! ((10#$VPN_PORT >= 1 && 10#$VPN_PORT <= 65535)); then
    die "VPN_PORT must be an integer from 1 to 65535"
fi
[[ "$VPN_RECONNECT_DELAY" =~ ^[0-9]+([.][0-9]+)?$ ]] \
    || die "VPN_RECONNECT_DELAY must be a non-negative number"

[ -n "$VPN_PASSWORD" ] && [ -n "$VPN_PASSWORD_FILE" ] \
    && die "set only one of VPN_PASSWORD and VPN_PASSWORD_FILE"
[ -n "$VPN_OTP" ] && [ -n "$VPN_OTP_FILE" ] \
    && die "set only one of VPN_OTP and VPN_OTP_FILE"

refresh_credentials
detect_uplink || die "no IPv4 default route found"
LAN_IFACE="${LAN_IFACE:-${UPLINK_DEV:-eth0}}"
log "uplink is $LAN_IFACE via ${UPLINK_GW:-<direct route>}"

create_ppp_device
enable_forwarding
pin_server_routes

if [ -n "$DNS_SERVERS" ]; then
    cp /etc/resolv.conf "$ORIGINAL_RESOLV_FILE" 2>/dev/null \
        || die "could not save the original /etc/resolv.conf"
fi

if is_on "$FIREWALL_ENABLED"; then
    select_iptables_backend
    setup_firewall
else
    warn "killswitch firewall is disabled"
fi

setup_policy_routing

trap shutdown TERM INT

while :; do
    run_once
    rc=$?
    [ "$STOPPING" = 1 ] && break
    log "openfortivpn exited (rc=$rc), reconnecting in ${VPN_RECONNECT_DELAY}s"
    sleep "$VPN_RECONNECT_DELAY"
done
