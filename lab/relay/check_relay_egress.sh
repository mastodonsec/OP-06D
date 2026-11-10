#!/bin/sh
# RC-47: Lab model relay: let the sealed scanner reach the planner model for lab runs
#
# Run INSIDE the relay container, as the relay user (the socat process's view):
#   docker compose -f lab/docker-compose.yml -f lab/model-relay.<mode>.yml \
#     exec -T -u relay model-relay sh /usr/local/bin/check_relay_egress.sh <mode>
#
# The relay must reach exactly its one upstream. Every other attempt is
# EXPECTED TO FAIL. Exit codes as lab/check_isolation.sh:
#   0 PASS   1 FAIL (relay reaches more than its upstream)   2 INCONCLUSIVE

set -u
MODE="${1:-}"
FAILS=0
CONTROL_FAILS=0

blocked() {
  desc="$1"; shift
  if timeout 8 "$@" >/dev/null 2>&1; then
    echo "FAIL  REACHABLE (this must be blocked): $desc"; FAILS=$((FAILS + 1))
  else
    echo "PASS  blocked, as expected:             $desc"
  fi
}
works() {
  desc="$1"; shift
  if timeout 15 "$@" >/dev/null 2>&1; then
    echo "ok    control works:                    $desc"
  else
    echo "BAD   control FAILED:                   $desc"; CONTROL_FAILS=$((CONTROL_FAILS + 1))
  fi
}

case "$MODE" in
  local|anthropic) ;;
  *) echo "usage: check_relay_egress.sh local|anthropic"; exit 2 ;;
esac

echo "------------------------------------------------------------------"
echo "OP-06D model relay egress check (mode: $MODE), as uid $(id -u)"
echo "------------------------------------------------------------------"

# The relay process (HAProxy, under init) must hold no capabilities.
for st in /proc/[0-9]*/status; do
  name="$(awk '/^Name:/{print $2}' "$st" 2>/dev/null)"
  [ "$name" = "haproxy" ] || continue
  for field in CapEff CapPrm CapInh CapAmb CapBnd; do
    val="$(awk -v f="$field:" '$1==f{print $2}' "$st")"
    if [ "$val" = "0000000000000000" ]; then
      echo "PASS  haproxy $field is empty"
    else
      echo "FAIL  haproxy $field is $val (must be 0000000000000000)"; FAILS=$((FAILS + 1))
    fi
  done
  uid="$(awk '/^Uid:/{print $2}' "$st")"
  if [ "$uid" = "0" ]; then echo "FAIL  haproxy runs as root"; FAILS=$((FAILS + 1)); else echo "PASS  haproxy runs as uid $uid"; fi
  found_relay=1
done
[ "${found_relay:-0}" = 1 ] || { echo "BAD   no haproxy process found"; CONTROL_FAILS=$((CONTROL_FAILS + 1)); }

if [ "$MODE" = local ]; then
  works   "TCP host.docker.internal:11434 (the upstream; host Ollama must be running)" socat -u /dev/null "TCP4:host.docker.internal:11434,connect-timeout=5"
  blocked "TCP api.anthropic.com:443"          socat -u /dev/null "TCP4:api.anthropic.com:443,connect-timeout=5"
  blocked "TCP host.docker.internal:80"        socat -u /dev/null "TCP4:host.docker.internal:80,connect-timeout=5"
  blocked "TCP host.docker.internal:445"       socat -u /dev/null "TCP4:host.docker.internal:445,connect-timeout=5"
  blocked "TCP host.docker.internal:2375"      socat -u /dev/null "TCP4:host.docker.internal:2375,connect-timeout=5"
else
  works   "TCP api.anthropic.com:443 (the upstream)" socat -u /dev/null "TCP4:api.anthropic.com:443,connect-timeout=5"
  blocked "TCP api.anthropic.com:80"           socat -u /dev/null "TCP4:api.anthropic.com:80,connect-timeout=5"
  blocked "TCP host.docker.internal:11434"     socat -u /dev/null "TCP4:host.docker.internal:11434,connect-timeout=5"
fi
blocked "TCP 1.1.1.1:443"                      socat -u /dev/null "TCP4:1.1.1.1:443,connect-timeout=5"
blocked "TCP 1.1.1.1:80"                       socat -u /dev/null "TCP4:1.1.1.1:80,connect-timeout=5"
blocked "TCP 8.8.8.8:53"                       socat -u /dev/null "TCP4:8.8.8.8:53,connect-timeout=5"
blocked "TCP example.com:443"                  socat -u /dev/null "TCP4:example.com:443,connect-timeout=5"
blocked "TCP github.com:443"                   socat -u /dev/null "TCP4:github.com:443,connect-timeout=5"
blocked "TCP 172.31.77.10:3000 (lab target)"   socat -u /dev/null "TCP4:172.31.77.10:3000,connect-timeout=5"
blocked "TCP 172.31.77.11:80 (lab target)"     socat -u /dev/null "TCP4:172.31.77.11:80,connect-timeout=5"
blocked "TCP6 [2606:4700:4700::1111]:443"      socat -u /dev/null "TCP6:[2606:4700:4700::1111]:443,connect-timeout=5"
echo "------------------------------------------------------------------"

if [ "$CONTROL_FAILS" -gt 0 ]; then
  echo "RESULT: INCONCLUSIVE ($CONTROL_FAILS control(s) failed; is the upstream up?)"; exit 2
fi
if [ "$FAILS" -gt 0 ]; then
  echo "RESULT: FAIL - the relay reaches more than its one upstream ($FAILS check(s)). Tear it down."; exit 1
fi
echo "RESULT: PASS - the relay reaches only its upstream ($MODE)."
exit 0
