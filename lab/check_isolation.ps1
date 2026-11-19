<#
.SYNOPSIS
  OP-06D lab isolation gate, Windows/PowerShell. Run BEFORE any scan.

.DESCRIPTION
  A wrapper: it runs lab/check_isolation.py (the same checks on every OS) with
  the same parameters and exits with its exit code. See that file for what is
  checked.

  Run from the repository root:
    pwsh -File lab\check_isolation.ps1
    pwsh -File lab\check_isolation.ps1 -WithInternetControl
  which is the same as:
    uv run python lab/check_isolation.py
    uv run python lab/check_isolation.py --with-internet-control

  Exit codes: 0 = PASS, 1 = FAIL (not isolated: stop), 2 = INCONCLUSIVE,
              3 = NOT RUN (Docker is unreachable or the lab stack is not up, so
                  nothing was checked; this says nothing about isolation).
#>
param(
  [string]$Compose = "lab/docker-compose.yml",
  [string]$Project = "rc-lab",
  [switch]$WithInternetControl
)

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
  Write-Host "RESULT: NOT RUN - uv is not installed or not on PATH." -ForegroundColor Yellow
  Write-Host "Nothing was checked. This is neither a PASS nor an isolation FAIL."
  Write-Host "Install uv (https://docs.astral.sh/uv/), then run this again."
  exit 3
}

$repo = Split-Path -Parent $PSScriptRoot
$checkArgs = @("run", "--project", $repo, "python", (Join-Path $PSScriptRoot "check_isolation.py"),
               "--compose", $Compose, "--project", $Project)
if ($WithInternetControl) { $checkArgs += "--with-internet-control" }
& uv @checkArgs
exit $LASTEXITCODE
