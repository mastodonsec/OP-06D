#!/bin/bash
# Red Cell lab isolation check (RC-19).
#
# Run INSIDE the scanner container, before any scan:
#   docker compose -f lab/docker-compose.yml exec -T scanner bash /lab/check_isolation.sh
#
# WHAT THIS SCRIPT DOES
#   It tries to reach the internet and neighbouring networks in several ways.
#   EVERY ONE OF THESE ATTEMPTS IS EXPECTED TO FAIL. A failed attempt prints
#   "PASS  blocked, as expected". An attempt that SUCCEEDS prints
#   "FAIL  REACHABLE" and means the lab is NOT isolated: STOP and tear it down.
#
# WHY CONTROLS COME FIRST
#   "Everything failed" proves nothing if the tools themselves are broken (no ping
#   capability, no DNS, stack not up). So first it checks that the SAME mechanisms
#   (ping, raw TCP, curl, name lookup) DO work to the lab targets. If a control
#   fails the result is INCONCLUSIVE (exit 2), never PASS.
#
# EXIT CODES
#   0  PASS          no egress detected, controls worked
#   1  FAIL          egress or a second network detected  -> STOP, do not scan
#   2  INCONCLUSIVE  could not run the checks / controls failed -> fix, rerun
#
# LIMIT
#   From inside a container this cannot see how Docker is configured on the host.
#   The host-side checks in lab/check_isolation.ps1 and lab/RUNBOOK.md (network is
#   `internal`, no published ports, one network per container) are part of the
#   same gate.

set -u

LAB_SUBNET_PREFIX="172.31.77."
JUICE_IP="172.31.77.10"
DVWA_IP="172.31.77.11"

FAILS=0
CONTROL_FAILS=0

say()   { printf '%s\n' "$*"; }
hr()    { printf '%s\n' "------------------------------------------------------------------"; }

# expect_blocked <description> <timeout-seconds> <command...>
# PASS when the command FAILS (nothing is reachable).
expect_blocked() {
  local desc="$1" to="$2"; shift 2
  if timeout "$to" "$@" >/dev/null 2>&1; then
    printf 'FAIL  REACHABLE (this must be blocked): %s\n' "$desc"
    FAILS=$((FAILS + 1))
  else
    printf 'PASS  blocked, as expected:             %s\n' "$desc"
  fi
}

# expect_works <description> <timeout-seconds> <command...>
# A control: must SUCCEED against the lab, otherwise the blocked results mean nothing.
expect_works() {
  local desc="$1" to="$2"; shift 2
  if timeout "$to" "$@" >/dev/null 2>&1; then
    printf 'ok    control works (in-lab):           %s\n' "$desc"
  else
    printf 'BAD   control FAILED (in-lab):          %s\n' "$desc"
    CONTROL_FAILS=$((CONTROL_FAILS + 1))
  fi
}

hr
say "Red Cell lab isolation check"
say "Every 'blocked' test below is EXPECTED TO FAIL to connect."
say "PASS = could not connect (good).  FAIL = connected (lab is NOT isolated)."
hr

# --- 0. preflight: the tools this script depends on must exist ---------------
for c in bash timeout curl ping nc ip getent awk grep; do
  if ! command -v "$c" >/dev/null 2>&1; then
    say "INCONCLUSIVE: required command '$c' is missing; cannot run the check."
    exit 2
  fi
done

# --- 1. evidence --------------------------------------------------------------
say "Interfaces:"
ip -brief addr 2>&1 | sed 's/^/  /'
say "IPv4 routes:"
ip -4 route 2>&1 | sed 's/^/  /'
say "IPv6 routes:"
ip -6 route 2>&1 | sed 's/^/  /'
say "Resolver config:"
sed 's/^/  /' /etc/resolv.conf 2>&1
hr

# --- 2. controls: the same mechanisms must work INSIDE the lab ---------------
say "Controls (these must work, or the blocked tests prove nothing):"
expect_works "ping $JUICE_IP (ICMP/raw sockets)"        6 ping -c1 -W3 "$JUICE_IP"
expect_works "ping $DVWA_IP"                              6 ping -c1 -W3 "$DVWA_IP"
expect_works "TCP $JUICE_IP:3000 (bash /dev/tcp)"        6 bash -c "exec 3<>/dev/tcp/$JUICE_IP/3000"
expect_works "TCP $DVWA_IP:80 (nc)"                       6 nc -z -w3 "$DVWA_IP" 80
expect_works "name lookup juice-shop.lab"                 6 getent hosts juice-shop.lab
expect_works "name lookup dvwa.lab"                       6 getent hosts dvwa.lab
expect_works "HTTP http://juice-shop.lab:3000/ (curl)"   12 curl -sS --noproxy '*' --max-time 10 -o /dev/null http://juice-shop.lab:3000/
expect_works "HTTP http://dvwa.lab/ (curl)"              12 curl -sS --noproxy '*' --max-time 10 -o /dev/null http://dvwa.lab/
hr

if [ "$CONTROL_FAILS" -gt 0 ]; then
  say "RESULT: INCONCLUSIVE"
  say "$CONTROL_FAILS control(s) failed. The stack may still be starting (DVWA takes a"
  say "while), or a tool is not working. Wait and rerun. This is NOT a pass."
  exit 2
fi

# --- 3. structure: exactly one network, no default route ----------------------
say "Structure checks:"

default_v4="$(ip -4 route show default 2>/dev/null)"
if [ -z "$default_v4" ]; then
  say "PASS  no IPv4 default route (nothing to route out through)"
else
  say "FAIL  IPv4 default route exists: $default_v4"
  FAILS=$((FAILS + 1))
fi

default_v6="$(ip -6 route show default 2>/dev/null)"
if [ -z "$default_v6" ]; then
  say "PASS  no IPv6 default route"
else
  say "FAIL  IPv6 default route exists: $default_v6"
  FAILS=$((FAILS + 1))
fi

# Exactly one non-loopback interface, inside the lab subnet. A second interface
# would mean the container is attached to a second (possibly routable) network.
ifaces="$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $2" "$4}')"
iface_count="$(printf '%s\n' "$ifaces" | grep -c .)"
if [ "$iface_count" -eq 1 ] && printf '%s' "$ifaces" | grep -q " ${LAB_SUBNET_PREFIX}"; then
  say "PASS  exactly one network interface, inside ${LAB_SUBNET_PREFIX}0/24 ($ifaces)"
else
  say "FAIL  expected exactly one interface in ${LAB_SUBNET_PREFIX}0/24, found $iface_count: $ifaces"
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
hr

# --- 5. verdict ----------------------------------------------------------------
if [ "$FAILS" -gt 0 ]; then
  say "RESULT: FAIL - EGRESS IS REACHABLE ($FAILS check(s) failed)"
  say ""
  say "STOP. The lab is NOT isolated. Do NOT run any scan."
  say "Tear it down:  docker compose -f lab/docker-compose.yml down"
  say "Then fix lab/docker-compose.yml (network must be 'internal: true', one network only)"
  exit 1
fi

say "RESULT: PASS - no egress. Every outbound attempt was blocked and the in-lab controls worked."
say ""
say "This covers the view from INSIDE the scanner only. Also complete the host-side"
say "checks (lab/check_isolation.ps1 or the RUNBOOK) before the first scan."
exit 0
