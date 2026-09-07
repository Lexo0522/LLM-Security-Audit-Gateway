package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Environment                     string
	Version                         string
	AllowDemoBootstrap              bool
	UpstreamAllowPrivateNetworks    bool
	ListenAddr                      string
	AdminAddr                       string
	MaxBodyBytes                    int
	MaxResponseBytes                int
	RequestTimeoutMS                int
	AuditEnabled                    bool
	FailClosed                      bool
	PostgresURL                     string
	PostgresPoolMaxConns            int
	PostgresConnMaxLifetimeMS       int
	PostgresConnMaxIdleMS           int
	OutboxClaimSize                 int
	RedisURL                        string
	KafkaBrokers                    []string
	KafkaAuditTopic                 string
	KafkaAuditDLQTopic              string
	KafkaConsumerGroup              string
	ClickHouseDSN                   string
	ConsumerListenAddr              string
	EncryptionKeyFile               string
	AdminSessionTTLMS               int
	AdminCookieSecureMode           string
	AdminTrustedOrigins             []string
	AdminLoginMaxFailures           int
	AdminLoginLockoutMS             int
	RateLimitRPS                    int
	RateLimitBurst                  int
	AuditorURL                      string
	AuditorModel                    string
	AuditorTimeoutMS                int
	AuditorConcurrency              int
	EventQueueSize                  int
	SSEAuditWindowBytes             int
	SSEMaxEventBytes                int
	HealthProbeIntervalMS           int
	HealthProbeTimeoutMS            int
	SnapshotRefreshIntervalMS       int
	AuditRecordsRetentionDays       int
	OutboxRetentionDays             int
	RetentionSweepIntervalMS        int
	UpstreamDeletionGracePeriodMS   int
	UpstreamDeletionBatchSize       int
	UpstreamDeletionSweepIntervalMS int
}

func Load() (Config, error) {
	// Security switches must fail startup instead of silently falling back to
	// the default on a typo: AUDIT_FAIL_CLOSED=yes must not degrade into
	// fail-open. Every malformed numeric or boolean value is collected here.
	var errs []error
	boolOpt := func(key string, fallback bool) bool {
		value, err := envBool(key, fallback)
		if err != nil {
			errs = append(errs, err)
		}
		return value
	}
	intOpt := func(key string, fallback int) int {
		value, err := envInt(key, fallback)
		if err != nil {
			errs = append(errs, err)
		}
		return value
	}
	cfg := Config{
		Environment:                  env("GATEWAY_ENV", "production"),
		AllowDemoBootstrap:           boolOpt("ALLOW_DEMO_BOOTSTRAP_RULES", false),
		UpstreamAllowPrivateNetworks: boolOpt("UPSTREAM_ALLOW_PRIVATE_NETWORKS", false),
		ListenAddr:                   env("GATEWAY_LISTEN_ADDR", ":8080"),
		AdminAddr:                    env("GATEWAY_ADMIN_ADDR", ":8081"),
		MaxBodyBytes:                 intOpt("MAX_BODY_BYTES", 4<<20),
		MaxResponseBytes:             intOpt("MAX_RESPONSE_BYTES", 16<<20),
		RequestTimeoutMS:             intOpt("REQUEST_TIMEOUT_MS", 120000),
		AuditEnabled:                 boolOpt("AUDIT_ENABLED", true),
		FailClosed:                   boolOpt("AUDIT_FAIL_CLOSED", false),
		PostgresURL:                  os.Getenv("POSTGRES_URL"),
		PostgresPoolMaxConns:         intOpt("PG_POOL_MAX_CONNS", 16),
		PostgresConnMaxLifetimeMS:    intOpt("PG_CONN_MAX_LIFETIME_MS", 1800000),
		PostgresConnMaxIdleMS:        intOpt("PG_CONN_MAX_IDLE_MS", 300000),
		OutboxClaimSize:              intOpt("OUTBOX_CLAIM_SIZE", 100),
		RedisURL:                     os.Getenv("REDIS_URL"),
		KafkaBrokers:                 envList("KAFKA_BROKERS"),
		KafkaAuditTopic:              env("KAFKA_AUDIT_TOPIC", "audit.events"),
		KafkaAuditDLQTopic:           env("KAFKA_AUDIT_DLQ_TOPIC", ""),
		KafkaConsumerGroup:           env("KAFKA_CONSUMER_GROUP", "audit-clickhouse-v1"),
		ClickHouseDSN:                os.Getenv("CLICKHOUSE_DSN"),
		ConsumerListenAddr:           env("AUDIT_CONSUMER_LISTEN_ADDR", ":9090"),
		EncryptionKeyFile:            env("GATEWAY_ENCRYPTION_KEY_FILE", "/var/lib/gateway/keys/encryption.key"),
		AdminSessionTTLMS:            intOpt("ADMIN_SESSION_TTL_MS", 86400000),
		AdminCookieSecureMode:        strings.ToLower(env("ADMIN_COOKIE_SECURE_MODE", "auto")),
		AdminTrustedOrigins:          envList("ADMIN_TRUSTED_ORIGINS"),
		AdminLoginMaxFailures:        intOpt("ADMIN_LOGIN_MAX_FAILURES", 5),
		AdminLoginLockoutMS:          intOpt("ADMIN_LOGIN_LOCKOUT_MS", 900000),

		RateLimitRPS:                    intOpt("RATE_LIMIT_RPS", 60),
		RateLimitBurst:                  intOpt("RATE_LIMIT_BURST", 120),
		AuditorURL:                      os.Getenv("AUDITOR_URL"),
		AuditorModel:                    env("AUDITOR_MODEL", "http-auditor"),
		AuditorTimeoutMS:                intOpt("AUDITOR_TIMEOUT_MS", 350),
		AuditorConcurrency:              intOpt("AUDITOR_CONCURRENCY", 8),
		EventQueueSize:                  intOpt("AUDIT_EVENT_QUEUE_SIZE", 1000),
		SSEAuditWindowBytes:             intOpt("SSE_AUDIT_WINDOW_BYTES", 16<<10),
		SSEMaxEventBytes:                intOpt("SSE_MAX_EVENT_BYTES", 256<<10),
		HealthProbeIntervalMS:           intOpt("HEALTH_PROBE_INTERVAL_MS", 5000),
		HealthProbeTimeoutMS:            intOpt("HEALTH_PROBE_TIMEOUT_MS", 750),
		SnapshotRefreshIntervalMS:       intOpt("SNAPSHOT_REFRESH_INTERVAL_MS", 30000),
		AuditRecordsRetentionDays:       intOpt("AUDIT_RECORDS_RETENTION_DAYS", 30),
		OutboxRetentionDays:             intOpt("OUTBOX_RETENTION_DAYS", 7),
		RetentionSweepIntervalMS:        intOpt("RETENTION_SWEEP_INTERVAL_MS", 3600000),
		UpstreamDeletionGracePeriodMS:   intOpt("UPSTREAM_DELETION_GRACE_PERIOD_MS", 86400000),
		UpstreamDeletionBatchSize:       intOpt("UPSTREAM_DELETION_BATCH_SIZE", 100),
		UpstreamDeletionSweepIntervalMS: intOpt("UPSTREAM_DELETION_SWEEP_INTERVAL_MS", 60000),
	}
	if len(errs) > 0 {
		return Config{}, errors.Join(errs...)
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.Environment == "" {
		c.Environment = "production"
	}
	if c.Environment != "production" && c.Environment != "development" && c.Environment != "test" {
		return fmt.Errorf("GATEWAY_ENV must be production, development, or test")
	}
	if c.AllowDemoBootstrap && c.Environment == "production" {
		return fmt.Errorf("ALLOW_DEMO_BOOTSTRAP_RULES is not allowed in production")
	}
	if c.UpstreamAllowPrivateNetworks && c.Environment == "production" {
		return fmt.Errorf("UPSTREAM_ALLOW_PRIVATE_NETWORKS is not allowed in production")
	}
	if c.AdminCookieSecureMode == "" {
		c.AdminCookieSecureMode = "auto"
	}
	if c.AdminCookieSecureMode != "auto" && c.AdminCookieSecureMode != "always" && c.AdminCookieSecureMode != "never" {
		return fmt.Errorf("ADMIN_COOKIE_SECURE_MODE must be auto, always, or never")
	}
	for _, origin := range c.AdminTrustedOrigins {
		if !strings.Contains(origin, "://") {
			return fmt.Errorf("ADMIN_TRUSTED_ORIGINS entries must include a scheme, e.g. https://admin.example.com")
		}
	}
	if c.PostgresURL == "" {
		return fmt.Errorf("POSTGRES_URL is required for gateway identity and administration")
	}
	return nil
}

func envList(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) (int, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", key, raw)
	}
	return value, nil
}

func envBool(key string, fallback bool) (bool, error) {
	raw := os.Getenv(key)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean (true/false), got %q", key, raw)
	}
	return value, nil
}
