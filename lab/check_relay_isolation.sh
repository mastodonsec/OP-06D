#!/bin/bash
# RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs
#
# Run INSIDE the scanner container while a model-relay overlay is up:
#   docker compose -f lab/docker-compose.yml -f lab/model-relay.<mode>.yml \
#     exec -T scanner bash /lab/check_relay_isolation.sh <local|anthropic> <relay-egress-ip>
# (lab/model_relay.py check <mode> runs it with the right arguments.)
#
# With the overlay up the scanner has a second interface (relaynet), so
# lab/check_isolation.sh fails by design. This check replaces it for that state:
# the same in-lab controls, the same structure checks extended to two networks,
# EVERY outbound attempt of lab/check_isolation.sh (verbatim), plus:
#   - the relay answers on its one listen port and nothing else
#   - the relay's outward-facing address is not reachable (no route through it)
#   - local:     api.anthropic.com does not resolve
#   - anthropic: api.anthropic.com resolves to the relay only; TLS to it validates
#                end to end; any other SNI through the relay is refused
#
# Exit codes as lab/check_isolation.sh: 0 PASS, 1 FAIL (stop), 2 INCONCLUSIVE.

set -u

MODE="${1:-}"
RELAY_EGRESS_IP="${2:-}"
LAB_SUBNET_PREFIX="172.31.77."
RELAY_SUBNET_PREFIX="172.31.78."
JUICE_IP="172.31.77.10"
DVWA_IP="172.31.77.11"
RELAY_IP="172.31.78.2"

case "$MODE" in
  local)     RELAY_PORT=11434; OTHER_PORT=443 ;;
  anthropic) RELAY_PORT=443;   OTHER_PORT=11434 ;;
  *) echo "usage: check_relay_isolation.sh local|anthropic <relay-egress-ip>"; exit 2 ;;
esac
if [ -z "$RELAY_EGRESS_IP" ]; then
  echo "INCONCLUSIVE: the relay's relay_egress address was not given"; exit 2
fi

FAILS=0
CONTROL_FAILS=0

say()   { printf '%s\n' "$*"; }
hr()    { printf '%s\n' "------------------------------------------------------------------"; }

expect_blocked() {
  local desc="$1" to="$2"; shift 2
  if timeout "$to" "$@" >/dev/null 2>&1; then
    printf 'FAIL  REACHABLE (this must be blocked): %s\n' "$desc"
    FAILS=$((FAILS + 1))
  else
    printf 'PASS  blocked, as expected:             %s\n' "$desc"
  fi
}

expect_works() {
  local desc="$1" to="$2"; shift 2
  if timeout "$to" "$@" >/dev/null 2>&1; then
    printf 'ok    control works:                    %s\n' "$desc"
  else
    printf 'BAD   control FAILED:                   %s\n' "$desc"
    CONTROL_FAILS=$((CONTROL_FAILS + 1))
  fi
}

# RC-60: Lab: run on Linux (Kali) and macOS, not only Windows
# Prints "<interface> <address>" for every IPv6 all-nodes (ff02::1) responder on
# every non-loopback interface that is neither this container nor a lab
# container (a lab container is recognised by the EUI-64 link-local address of a
# MAC this container learned over IPv4, i.e. after the controls). Exit 0 when it
# found one, 1 when not.
v6_foreign_responders() {
  local found=1 ifc known a
  for ifc in $(ip -o link show | awk -F': ' '$2 != "lo" {sub(/@.*/, "", $2); print $2}'); do
    known=" $(ip -6 -o addr show dev "$ifc" 2>/dev/null | awk '{sub(/\/.*/, "", $4); printf "%s ", $4}')"
    known="$known$(ip -4 neigh show dev "$ifc" 2>/dev/null | awk '/lladdr/ {print $3}' \
      | while IFS=: read -r m1 m2 m3 m4 m5 m6; do
          printf 'fe80::%x:%x:%x:%x ' $(( ((0x$m1 ^ 2) << 8) | 0x$m2 )) $(( (0x$m3 << 8) | 0xff )) \
            $(( (0xfe << 8) | 0x$m4 )) $(( (0x$m5 << 8) | 0x$m6 ))
        done)"
    for a in $(ping -6 -c2 -W2 "ff02::1%$ifc" 2>/dev/null | sed -n 's/.*bytes from \([0-9a-f:]*\)%.*/\1/p' | sort -u); do
      case "$known" in *" $a "*) continue ;; esac
      echo "$ifc $a"
      found=0
    done
  done
  return $found
}
export -f v6_foreign_responders

hr
say "OP-06D lab isolation check WITH the model relay ($MODE)"
say "Every 'blocked' test below is EXPECTED TO FAIL to connect."
hr

for c in bash timeout curl ping nc ip getent awk grep sort; do
  if ! command -v "$c" >/dev/null 2>&1; then
    say "INCONCLUSIVE: required command '$c' is missing; cannot run the check."
    exit 2
  fi
done

say "Interfaces:"
ip -brief addr 2>&1 | sed 's/^/  /'
say "IPv4 routes:"
ip -4 route 2>&1 | sed 's/^/  /'
say "IPv6 routes:"
ip -6 route 2>&1 | sed 's/^/  /'
say "Resolver config:"
sed 's/^/  /' /etc/resolv.conf 2>&1
say "IPv6 addresses:"
ip -6 -o addr show 2>&1 | awk '{print "  "$2" "$4}'
say "IPv6 disabled per interface (1 = disabled):"
for f in /proc/sys/net/ipv6/conf/*/disable_ipv6; do
  i="${f#/proc/sys/net/ipv6/conf/}"
  say "  ${i%/disable_ipv6}=$(cat "$f" 2>/dev/null)"
done
hr

say "Controls (these must work, or the blocked tests prove nothing):"
expect_works "ping $JUICE_IP (ICMP/raw sockets)"        6 ping -c1 -W3 "$JUICE_IP"
expect_works "ping $DVWA_IP"                              6 ping -c1 -W3 "$DVWA_IP"
expect_works "TCP $JUICE_IP:3000 (bash /dev/tcp)"        6 bash -c "exec 3<>/dev/tcp/$JUICE_IP/3000"
expect_works "TCP $DVWA_IP:80 (nc)"                       6 nc -z -w3 "$DVWA_IP" 80
expect_works "name lookup juice-shop.lab"                 6 getent hosts juice-shop.lab
expect_works "name lookup dvwa.lab"                       6 getent hosts dvwa.lab
expect_works "HTTP http://juice-shop.lab:3000/ (curl)"   12 curl -sS --noproxy '*' --max-time 10 -o /dev/null http://juice-shop.lab:3000/
expect_works "HTTP http://dvwa.lab/ (curl)"              12 curl -sS --noproxy '*' --max-time 10 -o /dev/null http://dvwa.lab/
expect_works "TCP relay $RELAY_IP:$RELAY_PORT (the relay's listen port)" 6 bash -c "exec 3<>/dev/tcp/$RELAY_IP/$RELAY_PORT"
if [ "$MODE" = local ]; then
  expect_works "HTTP http://$RELAY_IP:11434/api/version (host Ollama through the relay)" 15 \
    curl -sS --noproxy '*' --max-time 12 -o /dev/null --fail http://$RELAY_IP:11434/api/version
else
  expect_works "HTTPS https://api.anthropic.com/ through the relay, certificate validated" 20 \
    curl -sS --noproxy '*' --max-time 15 -o /dev/null https://api.anthropic.com/
fi
hr

if [ "$CONTROL_FAILS" -gt 0 ]; then
  say "RESULT: INCONCLUSIVE"
  say "$CONTROL_FAILS control(s) failed (stack still starting? relay upstream down?). This is NOT a pass."
  exit 2
fi

say "Structure checks:"
default_v4="$(ip -4 route show default 2>/dev/null)"
if [ -z "$default_v4" ]; then say "PASS  no IPv4 default route"; else say "FAIL  IPv4 default route exists: $default_v4"; FAILS=$((FAILS + 1)); fi
default_v6="$(ip -6 route show default 2>/dev/null)"
if [ -z "$default_v6" ]; then say "PASS  no IPv6 default route"; else say "FAIL  IPv6 default route exists: $default_v6"; FAILS=$((FAILS + 1)); fi

ifaces="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2" "$4}')"
iface_count="$(printf '%s\n' "$ifaces" | grep -c .)"
in_lab="$(printf '%s\n' "$ifaces" | grep -c " ${LAB_SUBNET_PREFIX}")"
in_relay="$(printf '%s\n' "$ifaces" | grep -c " ${RELAY_SUBNET_PREFIX}")"
if [ "$iface_count" -eq 2 ] && [ "$in_lab" -eq 1 ] && [ "$in_relay" -eq 1 ]; then
  say "PASS  exactly two interfaces: one in ${LAB_SUBNET_PREFIX}0/24, one in ${RELAY_SUBNET_PREFIX}0/24"
else
  say "FAIL  expected one interface in each of ${LAB_SUBNET_PREFIX}0/24 and ${RELAY_SUBNET_PREFIX}0/24, found: $ifaces"
  FAILS=$((FAILS + 1))
fi
hr

# --- 4. egress attempts: ALL EXPECTED TO FAIL ----------------------------------
say "Outbound attempts (ALL EXPECTED TO FAIL):"

# ICMP to well-known public resolvers
for ip in 1.1.1.1 8.8.8.8 9.9.9.9; do
  expect_blocked "ping $ip" 6 ping -c1 -W3 "$ip"
done

# TCP to public addresses (raw connect, no DNS involved)
expect_blocked "TCP 1.1.1.1:443"  7 bash -c 'exec 3<>/dev/tcp/1.1.1.1/443'
expect_blocked "TCP 1.1.1.1:80"   7 bash -c 'exec 3<>/dev/tcp/1.1.1.1/80'
expect_blocked "TCP 8.8.8.8:53"   7 bash -c 'exec 3<>/dev/tcp/8.8.8.8/53'
expect_blocked "TCP 8.8.8.8:443 (nc)" 7 nc -z -w4 8.8.8.8 443

# Name resolution of public names (also proves DNS does not forward out)
expect_blocked "DNS lookup example.com"  8 getent hosts example.com
expect_blocked "DNS lookup github.com"   8 getent hosts github.com
expect_blocked "DNS lookup site-outside.lab (the lab redirect target)" 8 getent hosts site-outside.lab

# HTTP(S) by name and by address; --noproxy so no proxy variable can help
expect_blocked "HTTPS https://example.com"       10 curl -sS --noproxy '*' --max-time 8 -o /dev/null https://example.com
expect_blocked "HTTP  http://example.com"        10 curl -sS --noproxy '*' --max-time 8 -o /dev/null http://example.com
expect_blocked "HTTPS https://api.github.com"    10 curl -sS --noproxy '*' --max-time 8 -o /dev/null https://api.github.com
expect_blocked "HTTPS https://1.1.1.1 (by address)" 10 curl -sSk --noproxy '*' --max-time 8 -o /dev/null https://1.1.1.1

# IPv6
expect_blocked "ping6 2606:4700:4700::1111" 6 ping -6 -c1 -W3 2606:4700:4700::1111
expect_blocked "HTTPS over IPv6 example.com" 10 curl -6 -sS --noproxy '*' --max-time 8 -o /dev/null https://example.com

# The Docker host and the default bridge's gateway must not be reachable either
expect_blocked "name lookup host.docker.internal"       6 getent hosts host.docker.internal
expect_blocked "ping 172.17.0.1 (default bridge gateway)" 6 ping -c1 -W3 172.17.0.1
expect_blocked "TCP 172.17.0.1:80"                       7 bash -c 'exec 3<>/dev/tcp/172.17.0.1/80'
expect_blocked "ping 192.168.65.254 (Docker Desktop host gateway)" 6 ping -c1 -W3 192.168.65.254
expect_blocked "ping 192.168.65.1"                       6 ping -c1 -W3 192.168.65.1

# RC-60: Lab: run on Linux (Kali) and macOS, not only Windows
# Each internal network's own gateway address: if a bridge holds it, it is an
# address of the Docker host. labnet and relaynet set inhibit_ipv4.
expect_blocked "ping 172.31.77.1 (labnet gateway: the Docker host)" 6 ping -c1 -W3 172.31.77.1
expect_blocked "TCP 172.31.77.1:22 (labnet gateway)"     7 bash -c 'exec 3<>/dev/tcp/172.31.77.1/22'
expect_blocked "TCP 172.31.77.1:80 (labnet gateway)"     7 bash -c 'exec 3<>/dev/tcp/172.31.77.1/80'
expect_blocked "TCP 172.31.77.1:443 (labnet gateway)"    7 bash -c 'exec 3<>/dev/tcp/172.31.77.1/443'
expect_blocked "TCP 172.31.77.1:11434 (labnet gateway)"  7 bash -c 'exec 3<>/dev/tcp/172.31.77.1/11434'
expect_blocked "ping 172.31.78.1 (relaynet gateway: the Docker host)" 6 ping -c1 -W3 172.31.78.1
expect_blocked "TCP 172.31.78.1:22 (relaynet gateway)"   7 bash -c 'exec 3<>/dev/tcp/172.31.78.1/22'
expect_blocked "TCP 172.31.78.1:80 (relaynet gateway)"   7 bash -c 'exec 3<>/dev/tcp/172.31.78.1/80'
expect_blocked "TCP 172.31.78.1:443 (relaynet gateway)"  7 bash -c 'exec 3<>/dev/tcp/172.31.78.1/443'
expect_blocked "TCP 172.31.78.1:11434 (relaynet gateway)" 7 bash -c 'exec 3<>/dev/tcp/172.31.78.1/11434'
expect_blocked "an IPv4 route via a gateway (ip -4 route)" 3 bash -c "ip -4 route | grep -q ' via '"
expect_blocked "an IPv6 route via a gateway (ip -6 route)" 3 bash -c "ip -6 route | grep -q ' via '"
expect_blocked "ARP reply from the labnet gateway 172.31.77.1" 6 bash -c "ping -c1 -W2 172.31.77.1 >/dev/null 2>&1; ip -4 neigh show 172.31.77.1 | grep -q lladdr"
expect_blocked "ARP reply from the relaynet gateway 172.31.78.1" 6 bash -c "ping -c1 -W2 172.31.78.1 >/dev/null 2>&1; ip -4 neigh show 172.31.78.1 | grep -q lladdr"

# IPv6 link-local: a bridge normally holds an fe80:: address, which reaches host
# services listening on [::] even when it holds no IPv4 address. The lab
# services disable IPv6 (compose sysctls), so nothing but lab containers may answer.
expect_blocked "IPv6 all-nodes ff02::1 reply from a non-lab address (every interface)" 15 bash -c v6_foreign_responders
for a in $(v6_foreign_responders | awk '{print $2"%"$1}'); do
  for port in 22 80 443 11434; do
    expect_blocked "TCP [$a]:$port (IPv6 link-local, not a lab container)" 7 nc -6 -z -w3 "$a" "$port"
  done
done

say "Relay-specific attempts (ALL EXPECTED TO FAIL):"
expect_blocked "TCP relay $RELAY_IP:$OTHER_PORT (not its listen port)" 7 bash -c "exec 3<>/dev/tcp/$RELAY_IP/$OTHER_PORT"
expect_blocked "TCP relay $RELAY_IP:22"                  7 bash -c "exec 3<>/dev/tcp/$RELAY_IP/22"
expect_blocked "TCP relay $RELAY_IP:80"                  7 bash -c "exec 3<>/dev/tcp/$RELAY_IP/80"
expect_blocked "ping relay egress side $RELAY_EGRESS_IP" 6 ping -c1 -W3 "$RELAY_EGRESS_IP"
expect_blocked "TCP relay egress side $RELAY_EGRESS_IP:$RELAY_PORT" 7 bash -c "exec 3<>/dev/tcp/$RELAY_EGRESS_IP/$RELAY_PORT"
if [ "$MODE" = local ]; then
  expect_blocked "name lookup api.anthropic.com"        6 getent hosts api.anthropic.com
  expect_blocked "HTTPS https://api.anthropic.com"      10 curl -sS --noproxy '*' --max-time 8 -o /dev/null https://api.anthropic.com/
else
  resolved="$(getent ahosts api.anthropic.com 2>/dev/null | awk '{print $1}' | sort -u | tr '\n' ' ')"
  if [ "$resolved" = "$RELAY_IP " ]; then
    say "PASS  api.anthropic.com resolves to the relay only ($RELAY_IP)"
  else
    say "FAIL  api.anthropic.com resolves to '$resolved' (must be the relay $RELAY_IP only)"
    FAILS=$((FAILS + 1))
  fi
  for sni in example.com claude.ai anthropic.com www.google.com; do
    expect_blocked "TLS SNI $sni through the relay (only api.anthropic.com is forwarded)" 12 \
      curl -sS --noproxy '*' --max-time 10 -o /dev/null --resolve "$sni:443:$RELAY_IP" "https://$sni/"
  done
  expect_blocked "plain TCP (no TLS ClientHello) through the relay" 10 \
    bash -c "exec 3<>/dev/tcp/$RELAY_IP/443; printf 'GET / HTTP/1.0\r\n\r\n' >&3; head -c1 <&3 | grep -q ."
fi
hr

if [ "$FAILS" -gt 0 ]; then
  say "RESULT: FAIL - THE LAB IS NOT ISOLATED WITH THE RELAY UP ($FAILS check(s) failed)"
  say "STOP. Tear it down:  uv run python lab/model_relay.py down"
  exit 1
fi
say "RESULT: PASS - with the $MODE relay up the scanner reaches only the lab targets and the relay's one port."
exit 0
