$ErrorActionPreference = 'Stop'
$compose = 'deploy/docker-compose.yml'
$project = 'audit-gateway-integration'
$env:POSTGRES_PASSWORD = 'audit-integration-password'
$env:INTEGRATION_POSTGRES_PORT = '15432'
$env:INTEGRATION_REDIS_PORT = '16379'
$env:INTEGRATION_KAFKA_PORT = '19092'
$env:POSTGRES_URL = "postgres://audit:$($env:POSTGRES_PASSWORD)@localhost:$($env:INTEGRATION_POSTGRES_PORT)/audit_gateway?sslmode=disable"
$env:REDIS_URL = "redis://localhost:$($env:INTEGRATION_REDIS_PORT)/0"
$env:KAFKA_BROKER = "localhost:$($env:INTEGRATION_KAFKA_PORT)"

docker version | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Docker Engine is unavailable or this session cannot access it.' }

$started = $false
try {
  docker compose -p $project -f $compose up -d postgres redis kafka
  $started = $true
  $deadline = (Get-Date).AddMinutes(2)
  do {
    try { $ready = (docker compose -p $project -f $compose exec -T postgres pg_isready -U audit -d audit_gateway) -match 'accepting connections' } catch { $ready = $false }
    if (-not $ready) { Start-Sleep -Seconds 2 }
  } while (-not $ready -and (Get-Date) -lt $deadline)
  if (-not $ready) { throw 'PostgreSQL did not become ready within two minutes.' }
  $deadline = (Get-Date).AddMinutes(2)
  do {
    try { docker compose -p $project -f $compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --list | Out-Null; $kafkaReady = $true } catch { $kafkaReady = $false }
    if (-not $kafkaReady) { Start-Sleep -Seconds 2 }
  } while (-not $kafkaReady -and (Get-Date) -lt $deadline)
  if (-not $kafkaReady) { throw 'Kafka did not become ready within two minutes.' }
  docker compose -p $project -f $compose exec -T kafka /opt/kafka/bin/kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic audit.events.integration --partitions 1 --replication-factor 1
  go test -tags=integration ./tests/integration
} finally {
  if ($started) { docker compose -p $project -f $compose down --volumes --remove-orphans }
}
