<#
Run infra smoke test locally.
Usage:
  .\run_smoke.ps1          # bring up infra, wait, run smoke test
  .\run_smoke.ps1 -TearDown  # tear down after test
#>
param(
  [switch]$TearDown
)

Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned
Push-Location -Path (Split-Path -Parent $MyInvocation.MyCommand.Definition)

Write-Host 'Starting docker compose (infra/)'
docker compose up -d --build

# Wait for Prometheus readiness
$ready = $false
for ($i=0; $i -lt 60; $i++) {
  try {
    $r = Invoke-WebRequest -UseBasicParsing -Uri http://localhost:9090/-/ready -TimeoutSec 2
    if ($r.StatusCode -eq 200) { $ready = $true; break }
  } catch {}
  Write-Host "Waiting for Prometheus... $i"
  Start-Sleep -Seconds 2
}

if (-not $ready) {
  Write-Host 'Prometheus did not become ready; showing status and logs'
  docker compose ps
  docker compose logs prometheus --tail 200
  Exit 1
}

Write-Host 'Prometheus ready'

try {
  Invoke-WebRequest -UseBasicParsing -Uri http://localhost:3000/api/health -TimeoutSec 2
  Write-Host 'Grafana reachable at http://localhost:3000'
} catch {
  Write-Host 'Grafana health check failed (it may still be starting)'
}

Write-Host 'Running pytest smoke test (from repo root)'
Push-Location ..\
python -m pytest -q tests/integration/test_e2e_flow.py
Pop-Location

if ($TearDown) {
  Write-Host 'Tearing down infra'
  docker compose down -v
}

Pop-Location
