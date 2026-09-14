FROM alpine:edge

LABEL org.opencontainers.image.title="openfortivpn" \
      org.opencontainers.image.description="Fortinet (PPP+TLS) VPN client container with a gluetun-style killswitch, usable as the network gateway for other containers" \
      org.opencontainers.image.source="https://github.com/paperbenni/dockerfiles" \
      org.opencontainers.image.url="https://github.com/paperbenni/dockerfiles/tree/master/openfortivpn"

# openfortivpn currently only ships in the Alpine "testing" repository,
# so add it explicitly (main/community are already present on edge).
RUN printf '%s\n' \
      "https://dl-cdn.alpinelinux.org/alpine/edge/main" \
      "https://dl-cdn.alpinelinux.org/alpine/edge/community" \
      "https://dl-cdn.alpinelinux.org/alpine/edge/testing" \
      > /etc/apk/repositories \
 && apk add --no-cache \
      openfortivpn \
      ppp \
      iptables \
      iptables-legacy \
      iproute2 \
      bash \
      ca-certificates \
      tzdata \
 && mkdir -p /etc/openfortivpn \
 && rm -rf /var/cache/apk/*

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY healthcheck.sh /usr/local/bin/healthcheck.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh /usr/local/bin/healthcheck.sh

# Sensible defaults; everything can be overridden at runtime.
ENV VPN_PORT=443 \
    VPN_SET_DNS=0 \
    VPN_PPPD_PEERDNS=1 \
    VPN_HALF_INTERNET_ROUTES=0 \
    VPN_INSECURE_SSL=0 \
    VPN_FULL_TUNNEL=on \
    VPN_RECONNECT_DELAY=5 \
    FIREWALL_ENABLED=on \
    HEALTHCHECK_TARGET= \
    TZ=UTC

HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck.sh"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]