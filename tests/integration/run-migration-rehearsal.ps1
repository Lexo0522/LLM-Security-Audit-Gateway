$ErrorActionPreference = 'Stop'

# This drill intentionally keeps the PostgreSQL volume so an upgrade decision is
# tested against an existing schema rather than a fresh database.
$compose = 'deploy/docker-compose.yml'
$project = 'audit-gateway-migration-rehearsal'
if ([string]::IsNullOrWhiteSpace($env:POSTGRES_PASSWORD)) {
  throw 'POSTGRES_PASSWORD must be supplied by the environment.'
}
$env:INTEGRATION_POSTGRES_PORT = if ($env:INTEGRATION_POSTGRES_PORT) { $env:INTEGRATION_POSTGRES_PORT } else { '15433' }
$env:POSTGRES_URL = "postgres://audit:$($env:POSTGRES_PASSWORD)@localhost:$($env:INTEGRATION_POSTGRES_PORT)/audit_gateway?sslmode=disable"
$env:PGPASSWORD = $env:POSTGRES_PASSWORD
$env:MIGRATION_REHEARSAL_LEGACY = '1'
$started = $false
$legacy = Join-Path ([System.IO.Path]::GetTempPath()) 'audit-gateway-legacy-schema.sql'
try {
  docker compose -p $project -f $compose up -d postgres
  if ($LASTEXITCODE -ne 0) { throw 'Failed to start the rehearsal PostgreSQL service.' }
  $started = $true
  $deadline = (Get-Date).AddMinutes(2)
  do {
    try { $ready = (docker compose -p $project -f $compose exec -T postgres pg_isready -U audit -d audit_gateway) -match 'accepting connections' } catch { $ready = $false }
    if (-not $ready) { Start-Sleep -Seconds 2 }
  } while (-not $ready -and (Get-Date) -lt $deadline)
  if (-not $ready) { throw 'PostgreSQL did not become ready within two minutes.' }

  $legacyParts = @(
    ((git show 1075ac6^:internal/storage/migrations/001_core.sql) -join "`n"),
    ((git show 1075ac6^:internal/storage/migrations/002_gateway_api_keys.sql) -join "`n"),
    ((git show 1075ac6^:internal/storage/migrations/003_policies.sql) -join "`n")
  )
  if ($LASTEXITCODE -ne 0) { throw 'Failed to read the historical schema fixture.' }
  $legacySQL = $legacyParts -join "`n"
  [System.IO.File]::WriteAllText($legacy, $legacySQL, [System.Text.UTF8Encoding]::new($false))
  Get-Content -Raw -Path $legacy | docker compose -p $project -f $compose exec -T postgres psql -U audit -d audit_gateway
  if ($LASTEXITCODE -ne 0) { throw 'Failed to install the historical schema fixture.' }

  go test -tags=integration -count=1 -run TestMigrationRejectsLegacySchema ./tests/integration
  if ($LASTEXITCODE -ne 0) { throw 'The legacy schema was not rejected as expected.' }
  Write-Host 'Migration rehearsal passed: the unsupported historical schema was rejected fail-closed.'
} finally {
  Remove-Item -Force -ErrorAction SilentlyContinue $legacy
  if ($started) {
    Write-Host "Rehearsal volume retained in Compose project '$project'. Inspect it before removing it with:"
    Write-Host "docker compose -p $project -f $compose down --volumes --remove-orphans"
  }
}
