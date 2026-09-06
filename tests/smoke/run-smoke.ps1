# Builds the full stack (including the two mock upstreams), boots it under a
# dedicated compose project with fresh volumes, runs the Go smoke test, and
# always tears the project down. Safe to run next to a developer stack only if
# ports 3000/8080 are free.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $root

$project = 'audit-gateway-smoke'
$composeArgs = @('-f', 'deploy/docker-compose.yml', '-f', 'deploy/docker-compose.smoke.yml')
$env:POSTGRES_PASSWORD = 'audit-smoke-password'
$env:CLICKHOUSE_PASSWORD = 'audit-smoke-password'
# Phase 2 needs the state phase 1 generated; the restart between the phases
# is orchestrated here so the Go test code contains no docker commands.
$env:SMOKE_STATE_FILE = Join-Path ([System.IO.Path]::GetTempPath()) ("smoke-state-" + [guid]::NewGuid().ToString() + ".json")
$env:SMOKE_REPO_ROOT = $root

docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is unavailable or this session cannot access it.' }

$started = $false
try {
  $started = $true
  # Always start from a clean project: a previous interrupted run (or manual
  # debugging) may have left volumes initialized with different passwords.
  docker compose -p $project @composeArgs down --volumes --remove-orphans
  # Build each service separately: compose's multi-service bake path fails
  # when the checkout path contains non-ASCII characters (gRPC session header
  # validation), while single-service builds are fine everywhere. This still
  # proves the images build end to end (Go modules and npm fetches included).
  foreach ($service in @('gateway', 'web', 'audit-consumer')) {
    docker compose -p $project @composeArgs build $service
    if ($LASTEXITCODE -ne 0) { throw "Failed to build the $service image." }
  }
  docker compose -p $project @composeArgs up -d --no-build
  if ($LASTEXITCODE -ne 0) { throw 'Failed to start the smoke stack.' }

  $deadline = (Get-Date).AddMinutes(6)
  $ready = $false
  do {
    try {
      $web = Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:3000/' -TimeoutSec 3
      $gateway = Invoke-WebRequest -UseBasicParsing -Uri 'http://localhost:8080/healthz' -TimeoutSec 3
      $ready = ($web.StatusCode -eq 200) -and ($gateway.StatusCode -eq 200)
    } catch { $ready = $false }
    if (-not $ready) { Start-Sleep -Seconds 3 }
  } while (-not $ready -and (Get-Date) -lt $deadline)
  if (-not $ready) {
    docker compose -p $project @composeArgs logs --tail 60 gateway web
    throw 'Smoke stack did not become ready within six minutes.'
  }

  # -count=1 keeps the acceptance run honest: a cached pass proves nothing.
  $env:SMOKE_PHASE = '1'
  go test -tags=smoke -count=1 -run TestComposeSmokePhase1 ./tests/smoke
  if ($LASTEXITCODE -ne 0) { throw 'Smoke phase 1 failed.' }

  docker compose -p $project @composeArgs restart gateway
  if ($LASTEXITCODE -ne 0) { throw 'Failed to restart the gateway container.' }

  $env:SMOKE_PHASE = '2'
  go test -tags=smoke -count=1 -run TestComposeSmokePhase2 ./tests/smoke
  if ($LASTEXITCODE -ne 0) { throw 'Smoke phase 2 failed.' }
} finally {
  if ($started) { docker compose -p $project @composeArgs down --volumes --remove-orphans }
  if ($env:SMOKE_STATE_FILE -and (Test-Path $env:SMOKE_STATE_FILE)) { Remove-Item $env:SMOKE_STATE_FILE -Force }
}
