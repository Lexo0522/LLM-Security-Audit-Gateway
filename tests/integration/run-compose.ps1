$ErrorActionPreference = 'Stop'
$compose = 'deploy/docker-compose.yml'
$project = 'audit-gateway-integration'
$env:POSTGRES_PASSWORD = 'audit-integration-password'
$env:CLICKHOUSE_PASSWORD = 'audit-integration-password'
$env:INTEGRATION_POSTGRES_PORT = '15432'
$env:INTEGRATION_REDIS_PORT = '16379'
$env:INTEGRATION_KAFKA_PORT = '19092'
$env:INTEGRATION_CLICKHOUSE_PORT = '18123'
$env:POSTGRES_URL = "postgres://audit:$($env:POSTGRES_PASSWORD)@localhost:$($env:INTEGRATION_POSTGRES_PORT)/audit_gateway?sslmode=disable"
$env:REDIS_URL = "redis://localhost:$($env:INTEGRATION_REDIS_PORT)/0"
$env:KAFKA_BROKERS = "localhost:$($env:INTEGRATION_KAFKA_PORT)"
$env:CLICKHOUSE_DSN = "http://audit:$($env:CLICKHOUSE_PASSWORD)@localhost:$($env:INTEGRATION_CLICKHOUSE_PORT)/default"

docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is unavailable or this session cannot access it.' }

$started = $false
try {
  $started = $true
  docker compose -p $project -f $compose up -d postgres redis kafka clickhouse
  if ($LASTEXITCODE -ne 0) { throw 'Failed to start integration dependencies.' }
  $deadline = (Get-Date).AddMinutes(2)
  do {
    # try/catch keeps Windows PowerShell 5.1 from turning a not-ready-yet
    # stderr line into a terminating error ($ErrorActionPreference = 'Stop').
    try { $ready = (docker compose -p $project -f $compose exec -T postgres pg_isready -U audit -d audit_gateway) -match 'accepting connections' } catch { $ready = $false }
    if (-not $ready) { Start-Sleep -Seconds 2 }
  } while (-not $ready -and (Get-Date) -lt $deadline)
  if (-not $ready) { throw 'PostgreSQL did not become ready within two minutes.' }
  $deadline = (Get-Date).AddMinutes(2)
  do {
    try {
      docker compose -p $project -f $compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list 2>$null | Out-Null
      $kafkaReady = $LASTEXITCODE -eq 0
    } catch { $kafkaReady = $false }
    if (-not $kafkaReady) { Start-Sleep -Seconds 2 }
  } while (-not $kafkaReady -and (Get-Date) -lt $deadline)
  if (-not $kafkaReady) { throw 'Kafka did not become ready within two minutes.' }

  $deadline = (Get-Date).AddMinutes(2)
  do {
    try {
      docker compose -p $project -f $compose exec -T clickhouse clickhouse-client --user audit --password $env:CLICKHOUSE_PASSWORD --query 'SELECT 1' 2>$null | Out-Null
      $clickhouseReady = $LASTEXITCODE -eq 0
    } catch { $clickhouseReady = $false }
    if (-not $clickhouseReady) { Start-Sleep -Seconds 2 }
  } while (-not $clickhouseReady -and (Get-Date) -lt $deadline)
  if (-not $clickhouseReady) { throw 'ClickHouse did not become ready within two minutes.' }
  foreach ($topic in @('audit.events.integration', 'audit.events.clickhouse.integration', 'audit.events.clickhouse.integration.dlq')) {
    docker compose -p $project -f $compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic $topic --partitions 1 --replication-factor 1
    if ($LASTEXITCODE -ne 0) { throw "Failed to create integration topic $topic." }
  }
  go test -tags=integration -count=1 ./tests/integration
  if ($LASTEXITCODE -ne 0) { throw 'Integration tests failed.' }
} finally {
  if ($started) { docker compose -p $project -f $compose down --volumes --remove-orphans }
}
