<#
.SYNOPSIS
  OP-06D lab isolation gate (RC-19), Windows/PowerShell. Run BEFORE any scan.

.DESCRIPTION
  Runs two groups of checks and exits non-zero unless ALL pass:

    A. Host-side (how Docker is configured):
         - the lab network is 'internal'
         - every lab container is attached to that one network only
         - no lab container publishes a port or uses host/privileged networking
    B. Inside the scanner container: lab/check_isolation.sh, which tries to reach
       the internet and neighbouring networks. EVERY attempt is EXPECTED TO FAIL.

  Optional -WithInternetControl also runs a throwaway container on Docker's
  DEFAULT bridge network and shows that it CAN reach the internet. That proves the
  test method can detect connectivity, so the lab's "blocked" results mean
  something. It makes one outbound HTTPS request (to example.com) from a
  throwaway container, not from the lab.

  Run from the repository root:
    powershell -File lab\check_isolation.ps1
    powershell -File lab\check_isolation.ps1 -WithInternetControl

  Exit codes: 0 = PASS, 1 = FAIL (not isolated: stop), 2 = INCONCLUSIVE.
#>
param(
  [string]$Compose = "lab/docker-compose.yml",
  [string]$Project = "rc-lab",
  [switch]$WithInternetControl
)

$ErrorActionPreference = "Continue"
$failed = $false
$network = "${Project}_labnet"

function Pass($m) { Write-Host "PASS  $m" -ForegroundColor Green }
function Fail($m) { Write-Host "FAIL  $m" -ForegroundColor Red; $script:failed = $true }

Write-Host "=== A. Host-side checks ==================================================="

# A1. the network is internal
$internal = (docker network inspect $network --format '{{.Internal}}' 2>$null)
if ($internal -eq "true") { Pass "network $network is internal (no gateway, no NAT)" }
else { Fail "network $network is not internal (got '$internal'). Is the stack up? Is 'internal: true' set?" }

# A2. which containers are on it, and what else they are attached to
$containers = @(docker network inspect $network --format '{{range $id, $c := .Containers}}{{$c.Name}} {{end}}' 2>$null) -split '\s+' | Where-Object { $_ }
if ($containers.Count -ne 3) { Fail "expected 3 containers on $network (juice-shop, dvwa, scanner), found $($containers.Count): $($containers -join ', ')" }
else { Pass "3 containers on ${network}: $($containers -join ', ')" }

foreach ($c in $containers) {
  $nets = (docker inspect $c --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}} {{end}}').Trim()
  if ($nets -eq $network) { Pass "$c is attached only to $network" }
  else { Fail "$c is attached to: $nets (must be only $network)" }

  $ports = (docker inspect $c --format '{{json .NetworkSettings.Ports}}')
  if ($ports -match '"HostPort"') { Fail "$c publishes ports to the host: $ports" }
  else { Pass "$c publishes no ports to the host" }

  $mode = (docker inspect $c --format '{{.HostConfig.NetworkMode}} privileged={{.HostConfig.Privileged}}')
  if ($mode -match '^host ' -or $mode -match 'privileged=true') { Fail "$c uses unsafe settings: $mode" }
  else { Pass "$c network mode / privilege OK ($mode)" }
}

# A3. optional positive control: the SAME kind of request works from the default bridge
if ($WithInternetControl) {
  Write-Host ""
  Write-Host "--- Control: a throwaway container on the DEFAULT bridge (expected to REACH the internet) ---"
  $img = "op06d-lab-scanner:nmap-7.93-nuclei-3.11.1-templates-10.5.1"
  docker run --rm --network bridge $img curl -sS --max-time 10 -o /dev/null -w "HTTP %{http_code}`n" https://example.com
  if ($LASTEXITCODE -eq 0) { Pass "control: default-bridge container reached the internet (so the lab's failures are meaningful)" }
  else { Write-Host "INCONCLUSIVE  control could not reach the internet from the default bridge; the host may be offline. 'Blocked' results are then not proof." -ForegroundColor Yellow; exit 2 }
}

Write-Host ""
Write-Host "=== B. Inside the scanner (every outbound attempt is EXPECTED TO FAIL) ===="
docker compose -f $Compose exec -T scanner bash /lab/check_isolation.sh
$inner = $LASTEXITCODE
if ($inner -eq 2) { Write-Host "INCONCLUSIVE inside the scanner. Not a pass." -ForegroundColor Yellow; exit 2 }
if ($inner -ne 0) { Fail "scanner-side check failed (exit $inner)" }

Write-Host ""
if ($failed) {
  Write-Host "RESULT: FAIL - THE LAB IS NOT PROVEN ISOLATED. DO NOT SCAN." -ForegroundColor Red
  Write-Host "Tear down:  docker compose -f $Compose down"
  exit 1
}
Write-Host "RESULT: PASS - lab isolation confirmed (host-side and from inside). You may proceed." -ForegroundColor Green
exit 0
