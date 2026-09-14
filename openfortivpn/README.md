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
- Automatic reconnect loop with freshly built config.
- Killswitch firewall: if the tunnel drops, traffic cannot leak out of the
  physical interface.
- NAT + MSS clamping for containers using it as a gateway.
- Healthcheck based on the tunnel interface.
- Multi-arch: `linux/amd64` and `linux/arm64`.

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
  -e VPN_HOST=vpn.uni-freiburg.de \
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
      VPN_HOST: vpn.uni-freiburg.de
      VPN_USER: youruser
      VPN_PASSWORD: yourpassword
      # VPN_TRUSTED_CERT: "aa:bb:..."   # if the gateway uses a self-signed cert
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
| `VPN_INSECURE_SSL` | `0` | Set to `1` to skip certificate verification (not recommended). |
| `VPN_MIN_TLS` | *(empty)* | Minimum TLS version, e.g. `1.2`. |
| `VPN_SET_DNS` | `0` | Let openfortivpn rewrite `/etc/resolv.conf` with the DNS servers pushed by the gateway. |
| `VPN_PPPD_PEERDNS` | `1` | Let pppd pick up peer DNS. |
| `VPN_HALF_INTERNET_ROUTES` | `0` | openfortivpn `half-internet-routes`. |
| `VPN_FULL_TUNNEL` | `on` | Route *all* traffic through the tunnel (`on`/`off`). |
| `VPN_RECONNECT_DELAY` | `5` | Seconds between reconnect attempts. |
| `VPN_EXTRA_ARGS` | *(empty)* | Extra flags appended to the `openfortivpn` command. |
| `FIREWALL_ENABLED` | `on` | Enable the killswitch firewall. |
| `LAN_IFACE` | auto-detected | Physical interface used for the control channel. |
| `LAN_SUBNET` | *(empty)* | Restrict forwarded traffic to this source subnet. |
| `DNS_SERVERS` | *(empty)* | Comma-separated DNS servers written to `/etc/resolv.conf` once up. |
| `HEALTHCHECK_TARGET` | *(empty)* | Optional host that must be pingable through the tunnel. |

### Certificate trust

If the gateway uses a self-signed certificate, openfortivpn needs to know about
it. Get the digest and pass it as `VPN_TRUSTED_CERT`:

```sh
openssl s_client -connect vpn.uni-freiburg.de:443 -servername vpn.uni-freiburg.de </dev/null 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-Z' 'a-z'
```

Otherwise the first `openfortivpn` run prints the digest it saw in the logs.
As a last resort `VPN_INSECURE_SSL=1` disables verification.

## Killswitch

When `FIREWALL_ENABLED=on` (default) the container starts with an `iptables`
policy of `DROP` for `OUTPUT` and `FORWARD`. Only these are allowed:

- loopback and already-established connections,
- traffic leaving through the `ppp+` tunnel interface,
- the control channel to the resolved VPN gateway IP and port on the physical
  interface,
- DNS and DHCP on the physical interface (so reconnects and name resolution
  keep working),
- forwarded traffic between the tunnel and the local interface.

If the tunnel drops, nothing can escape through the physical interface, so
containers attached to this one are cut off rather than leaking.

## Switching the killswitch off

Set `FIREWALL_ENABLED=off` if you do not want the firewall rules at all (for
example if you already manage firewall rules somewhere else).

## Notes and limitations

- The image uses Alpine's `edge`/`testing` repositories because that is where
  `openfortivpn` lives. It may occasionally break; pin a digest if you care.
- Only IPv4 is handled by the killswitch.
- DNS is left to Docker by default (`VPN_SET_DNS=0`) so that resolving the
  gateway keeps working across reconnects. If your service needs names that
  only the VPN's DNS can resolve, set `VPN_SET_DNS=1` or point `DNS_SERVERS`
  at the VPN's resolver.
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