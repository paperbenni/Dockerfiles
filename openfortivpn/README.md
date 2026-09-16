# openfortivpn

A small Fortinet VPN client container, in the spirit of
[gluetun](https://github.com/qdm12/gluetun) but for **openfortivpn**
(PPP+TLS). It authenticates with a FortiGate gateway and then acts as a
gateway for other containers: point them at it with
`network_mode: "service:openfortivpn"` and all their traffic goes through the
tunnel.

Typical use case: a service that can only reach a server behind a university
or company Forti VPN.

## Features

- Config through environment variables (no config files to write).
- Simple username/password login (realm, OTP, client certificates optional).
- Automatic reconnect loop that rereads password and OTP secret files.
- Fail-closed IPv4/IPv6 killswitch firewall with a narrowly scoped exception
  for Docker's embedded DNS resolver.
- Optional NAT + MSS clamping when used as a routed gateway.
- Healthcheck based on the tunnel interface.
- Multi-arch OCI image: `linux/amd64`, `linux/arm64`, and `linux/arm/v7`.

## Quick start

### 1. Host preparation

openfortivpn needs the `ppp` kernel modules and a `/dev/ppp` device.

```sh
# on the docker host
sudo modprobe ppp_generic ppp_async ppp_deflate
```

Most hosts will then have `/dev/ppp`. Containers need `NET_ADMIN`, and access
to that device.

### 2. Run the gateway

```sh
docker run -d \
  --name openfortivpn \
  --cap-add=NET_ADMIN \
  --cap-add=NET_RAW \
  --device=/dev/ppp \
  -e VPN_HOST=fortivpn.uni-freiburg.de \
  -e VPN_USER=youruser \
  -e VPN_PASSWORD=yourpassword \
  --restart unless-stopped \
  paperbenni/openfortivpn
```

If `/dev/ppp` is not available on the host you can run the container with
`--privileged` (the entrypoint will create the node itself), or pass
`--device-cgroup-rule='c 108:0 rmw' --cap-add=MKNOD`.

### 3. Attach your service to the tunnel

```sh
docker run -d \
  --name myservice \
  --network=container:openfortivpn \
  myimage
```

Everything `myservice` sends now leaves through the Forti VPN.

### docker compose

```yaml
services:
  openfortivpn:
    image: paperbenni/openfortivpn
    container_name: openfortivpn
    cap_add:
      - NET_ADMIN
      - NET_RAW
    devices:
      - /dev/ppp:/dev/ppp
    environment:
      VPN_HOST: fortivpn.uni-freiburg.de
      VPN_USER: youruser
      VPN_PASSWORD: yourpassword
      # VPN_TRUSTED_CERT: "aabb..."   # 64 hex characters, without colons
    restart: unless-stopped

  myservice:
    image: myimage
    network_mode: "service:openfortivpn"
    depends_on:
      - openfortivpn
```

> With `network_mode: "service:..."` the service has no own IP. Reach it from
> other containers by using the `openfortivpn` container name, and don't
> publish ports on `myservice` directly.

## Configuration

| Variable | Default | Description |
| --- | --- | --- |
| `VPN_HOST` | *(required)* | FortiGate hostname or IP. |
| `VPN_PORT` | `443` | Gateway port. |
| `VPN_USER` | *(empty)* | Username. |
| `VPN_PASSWORD` | *(empty)* | Password. |
| `VPN_PASSWORD_FILE` | *(empty)* | Read the password from a file instead (e.g. a docker secret). |
| `VPN_OTP` | *(empty)* | One-time password, if the gateway asks for one. |
| `VPN_OTP_FILE` | *(empty)* | Read the OTP from a file. |
| `VPN_REALM` | *(empty)* | Authentication realm. |
| `VPN_TRUSTED_CERT` | *(empty)* | SHA-256 digest of the gateway certificate to trust. |
| `VPN_CLIENT_CERT` | *(empty)* | Client certificate for certificate auth. |
| `VPN_CLIENT_KEY` | *(empty)* | Client key for certificate auth. |
| `VPN_CA_FILE` | *(empty)* | Custom CA bundle. |
| `VPN_SNI` | *(empty)* | TLS SNI to send. |
| `VPN_INSECURE_SSL` | `0` | Allow legacy TLS protocols/ciphers. This does **not** disable certificate verification. |
| `VPN_MIN_TLS` | *(empty)* | Minimum TLS version, e.g. `1.2`. |
| `VPN_SET_DNS` | `0` | Let openfortivpn rewrite `/etc/resolv.conf` with the DNS servers pushed by the gateway. |
| `VPN_PPPD_PEERDNS` | `0` | Let pppd pick up peer DNS. Leave disabled when openfortivpn or `DNS_SERVERS` manages DNS. |
| `VPN_HALF_INTERNET_ROUTES` | `0` | openfortivpn `half-internet-routes`. |
| `VPN_FULL_TUNNEL` | `on` | Route *all* traffic through the tunnel (`on`/`off`). |
| `VPN_SET_ROUTES` | `1` | Install routes pushed by the gateway (`1`/`0`). With `0`, only `VPN_ROUTES` use the tunnel. |
| `VPN_ROUTES` | *(empty)* | Extra IPv4 subnets routed through the tunnel, e.g. `132.230.0.0/16`. Host bits are normalized. |
| `VPN_EXCLUDE_ROUTES` | `100.64.0.0/10` | Comma-separated IPv4 subnets kept on the physical uplink for locally initiated traffic (e.g. Tailscale, LAN). Host bits are normalized. |
| `VPN_RECONNECT_DELAY` | `5` | Seconds between reconnect attempts. |
| `VPN_EXTRA_ARGS` | *(empty)* | Extra flags appended to the `openfortivpn` command. |
| `FIREWALL_ENABLED` | `on` | Enable the killswitch firewall. |
| `LAN_IFACE` | auto-detected | LAN-side interface for traffic forwarded back from the tunnel. The VPN control uplink is detected from the initial default route. |
| `LAN_SUBNET` | *(empty)* | Restrict forwarded traffic to this source subnet. |
| `DNS_SERVERS` | *(empty)* | Comma-separated DNS servers written to `/etc/resolv.conf` once up. |
| `HEALTHCHECK_TARGET` | *(empty)* | Optional host that must be pingable through the tunnel. |

### Certificate trust

If the gateway uses a self-signed certificate, openfortivpn needs to know about
it. Get the digest and pass it as `VPN_TRUSTED_CERT`:

```sh
openssl s_client -connect fortivpn.uni-freiburg.de:443 -servername fortivpn.uni-freiburg.de </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z'
```

Otherwise the first `openfortivpn` run prints the digest it saw in the logs.
`VPN_INSECURE_SSL=1` only enables legacy TLS protocols and ciphers; it does not
disable certificate verification.

## Killswitch

When `FIREWALL_ENABLED=on` (default), dedicated firewall chains reject output,
input, and forwarded traffic unless it is one of the following:

- loopback traffic and replies to permitted inbound connections,
- inbound traffic addressed to the container's directly attached subnets;
  Docker's published-port configuration determines which host ports reach it,
- traffic leaving through the `ppp+` tunnel interface,
- the control channel to the resolved VPN gateway IP and port on the physical
  interface,
- forwarded traffic between the tunnel and the local interface.

The firewall is installed before the gateway is resolved. The configured DNS
resolvers are opened first; afterward, only the resolved gateway addresses are
opened for the VPN control connection and pinned to the physical uplink. A
failed lookup leaves the rest of the killswitch closed. IPv6 output is blocked
because this image establishes an IPv4 PPP tunnel.

The IPv4 resolvers in `/etc/resolv.conf` are pinned to the physical uplink and
allowed only on TCP/UDP port 53. This includes Docker's embedded resolver when
present and preserves Compose service discovery and reconnect behavior, but
means DNS queries are the one intentional exception to the killswitch. Set
`VPN_SET_DNS=1` or `DNS_SERVERS` to use DNS supplied/reachable through the VPN
while connected.

## Published ports stay reachable

Replies to inbound connections (published ports reached from LAN,
Tailscale, ...) are automatically routed back via the physical uplink using
connection marking and a dedicated policy-routing table. This works with a
full-tunnel default route, while locally initiated traffic still uses the
tunnel. Routing is reconciled every 10 seconds while connected, so routes
rewritten by `pppd` are repaired automatically.

No additional firewall port list is needed. Docker publishes ports in the host
network namespace, so the normal `-p HOST_PORT:CONTAINER_PORT` configuration
remains the boundary controlling which services are exposed.

## Switching the killswitch off

Set `FIREWALL_ENABLED=off` if you do not want this container to install any
iptables rules (for example if you already manage them somewhere else). This
also disables automatic connection marking for published-port replies; your
external firewall/routing setup must handle those replies when full-tunnel
routing is enabled.

## Notes and limitations

- The image uses Alpine's `edge`/`testing` repositories because that is where
  `openfortivpn` lives. It may occasionally break; pin a digest if you care.
- DNS is left to Docker by default (`VPN_SET_DNS=0`) so that resolving the
  gateway and Compose service names keep working across reconnects. This is a
  deliberate DNS exception to the traffic killswitch. If your service needs
  private DNS, set `VPN_SET_DNS=1` or point `DNS_SERVERS` at the VPN resolver.
- Routing *all* traffic (`VPN_FULL_TUNNEL=on`) replaces the default route with
  the tunnel. If you only need the networks the gateway pushes, set it to
  `off` and openfortivpn will install just the routes it is told to.
- If your gateway blocks ICMP, leave `HEALTHCHECK_TARGET` empty; the
  healthcheck then only verifies that the `ppp` interface is up.

## CI

`.github/workflows/openfortivpn.yml` builds and pushes this image to Docker
Hub on changes under `openfortivpn/`. It expects these repository secrets:

- `DOCKERHUB_TOKEN` — a Docker Hub access token (required).
- `DOCKERHUB_USERNAME` — the Docker Hub account (optional, defaults to
  `paperbenni`).
