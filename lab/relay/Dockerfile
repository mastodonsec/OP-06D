# RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs
#
# The model relay: HAProxy (TCP mode) forwarding ONE upstream (local Ollama, or
# api.anthropic.com:443 as raw passthrough filtered on the TLS SNI), behind an
# iptables egress allowlist that the entrypoint applies before dropping every
# capability. socat is installed only as the probe tool of check_relay_egress.sh. Used only by the
# opt-in overlays lab/model-relay.local.yml / lab/model-relay.anthropic.yml.
#
# Pins:
#   base  alpine:3.24 (3.24.4) @ sha256:f59abe65... (multi-arch index digest)
# The apk packages come from the alpine 3.24 branch at build time; the build
# prints their exact versions (and writes them to /opt/relay-versions.txt).

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf

RUN apk add --no-cache haproxy socat iptables setpriv \
 && addgroup -S -g 1001 relay \
 && adduser -S -D -H -u 1001 -G relay -s /sbin/nologin relay \
 && apk list --installed 2>/dev/null | grep -E '^(haproxy|socat|iptables|setpriv)-[0-9]' | sort | tee /opt/relay-versions.txt \
 && [ "$(wc -l < /opt/relay-versions.txt)" -eq 4 ]

COPY relay-entrypoint.sh /usr/local/bin/relay-entrypoint.sh
COPY check_relay_egress.sh /usr/local/bin/check_relay_egress.sh
RUN chmod 0555 /usr/local/bin/relay-entrypoint.sh /usr/local/bin/check_relay_egress.sh

ENTRYPOINT ["/usr/local/bin/relay-entrypoint.sh"]
