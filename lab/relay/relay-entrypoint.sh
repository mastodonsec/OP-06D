#!/bin/sh
# RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs
#
# Usage (as the container command): relay-entrypoint.sh local|anthropic
#
#   local      listen RELAY_BIND:11434 -> host.docker.internal:11434 (host Ollama)
#   anthropic  listen RELAY_BIND:443   -> api.anthropic.com:443, raw TCP passthrough
#              (no TLS termination); a connection is forwarded only if its TLS
#              ClientHello carries SNI api.anthropic.com, otherwise it is closed
#
# Order, all as root and fail-closed (set -e: any failure exits before the relay starts):
#   1. resolve the one upstream to IPv4 addresses
#   2. iptables: OUTPUT allows only loopback (Docker's embedded DNS), replies, and
#      TCP to those addresses on the upstream port; INPUT allows only the relay
#      network to the listen port; FORWARD drops; IPv6 drops everything
#   3. exec HAProxy as the unprivileged relay user with every capability dropped
#      (effective, permitted, inheritable, ambient and bounding) and no_new_privs

set -eu

RELAY_NET="${RELAY_NET:-172.31.78.0/24}"
RELAY_BIND="${RELAY_BIND:-}"
CFG=/run/relay/haproxy.cfg

die() { echo "relay: $*" >&2; exit 1; }

[ "$#" -eq 1 ] || die "exactly one upstream mode is allowed (local|anthropic)"
case "$1" in
  local)     UP_HOST="host.docker.internal"; UP_PORT=11434; LISTEN_PORT=11434 ;;
  anthropic) UP_HOST="api.anthropic.com";    UP_PORT=443;   LISTEN_PORT=443 ;;
  *) echo "usage: relay-entrypoint.sh local|anthropic" >&2; exit 64 ;;
esac

[ -n "$RELAY_BIND" ] || die "RELAY_BIND is not set"
ip -4 -o addr show | awk '{print $4}' | grep -qx "${RELAY_BIND}/[0-9]*" \
  || die "RELAY_BIND $RELAY_BIND is not an address of this container"

UP_IPS="$(getent ahostsv4 "$UP_HOST" | awk '{print $1}' | sort -u)"
[ -n "$UP_IPS" ] || die "cannot resolve $UP_HOST"

ip6tables -P INPUT DROP
ip6tables -P FORWARD DROP
ip6tables -P OUTPUT DROP
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT

iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -p tcp -s "$RELAY_NET" -d "$RELAY_BIND" --dport "$LISTEN_PORT" -j ACCEPT
iptables -P INPUT DROP
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for ip in $UP_IPS; do
  iptables -A OUTPUT -p tcp -d "$ip" --dport "$UP_PORT" -j ACCEPT
done
iptables -P OUTPUT DROP

mkdir -p /run/relay
{
  echo "global"
  echo "  maxconn 64"
  echo "  log stdout format raw local0"
  echo "defaults"
  echo "  mode tcp"
  echo "  log global"
  echo "  option tcplog"
  echo "  timeout connect 10s"
  echo "  timeout client 900s"
  echo "  timeout server 900s"
  echo "frontend model_in"
  echo "  bind ${RELAY_BIND}:${LISTEN_PORT}"
  if [ "$1" = anthropic ]; then
    echo "  tcp-request inspect-delay 5s"
    echo "  tcp-request content accept if { req.ssl_hello_type 1 } { req.ssl_sni -m str api.anthropic.com }"
    echo "  tcp-request content reject"
  fi
  echo "  default_backend model_up"
  echo "backend model_up"
  echo "  server upstream ipv4@${UP_HOST}:${UP_PORT}"
} > "$CFG"
chmod 0444 "$CFG"
haproxy -c -q -f "$CFG"

echo "relay: mode=$1 listen=$RELAY_BIND:$LISTEN_PORT upstream=$UP_HOST:$UP_PORT allowed=$(echo $UP_IPS | tr ' ' ',')"
cat /opt/relay-versions.txt >&2

exec setpriv --reuid=relay --regid=relay --clear-groups \
  --inh-caps=-all --ambient-caps=-all --bounding-set=-all --no-new-privs \
  haproxy -db -f "$CFG"
