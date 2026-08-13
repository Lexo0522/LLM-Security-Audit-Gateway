package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	Environment               string
	AllowDemoBootstrap        bool
	ListenAddr                string
	AdminAddr                 string
	UpstreamURL               string
	UpstreamAPIKey            string
	MaxBodyBytes              int
	MaxResponseBytes          int
	RequestTimeoutMS          int
	AuditEnabled              bool
	FailClosed                bool
	PostgresURL               string
	RedisURL                  string
	KafkaBrokers              []string
	KafkaAuditTopic           string
	AdminToken                string
	RateLimitRPS              int
	RateLimitBurst            int
	AuditorURL                string
	AuditorModel              string
	AuditorTimeoutMS          int
	AuditorConcurrency        int
	EventQueueSize            int
	APIKeyPepper              string
	SSEAuditWindowBytes       int
	SSEMaxEventBytes          int
	HealthProbeIntervalMS     int
	HealthProbeTimeoutMS      int
	SnapshotRefreshIntervalMS int
}

func Load() Config {
	return Config{
		Environment:               env("GATEWAY_ENV", "production"),
		AllowDemoBootstrap:        envBool("ALLOW_DEMO_BOOTSTRAP_RULES", false),
		ListenAddr:                env("GATEWAY_LISTEN_ADDR", ":8080"),
		AdminAddr:                 env("GATEWAY_ADMIN_ADDR", ":8081"),
		UpstreamURL:               strings.TrimRight(env("NEWAPI_BASE_URL", "http://newapi:3000"), "/"),
		UpstreamAPIKey:            os.Getenv("NEWAPI_API_KEY"),
		MaxBodyBytes:              envInt("MAX_BODY_BYTES", 4<<20),
		MaxResponseBytes:          envInt("MAX_RESPONSE_BYTES", 16<<20),
		RequestTimeoutMS:          envInt("REQUEST_TIMEOUT_MS", 120000),
		AuditEnabled:              envBool("AUDIT_ENABLED", true),
		FailClosed:                envBool("AUDIT_FAIL_CLOSED", false),
		PostgresURL:               os.Getenv("POSTGRES_URL"),
		RedisURL:                  os.Getenv("REDIS_URL"),
		KafkaBrokers:              envList("KAFKA_BROKERS"),
		KafkaAuditTopic:           env("KAFKA_AUDIT_TOPIC", "audit.events"),
		AdminToken:                os.Getenv("ADMIN_API_TOKEN"),
		RateLimitRPS:              envInt("RATE_LIMIT_RPS", 60),
		RateLimitBurst:            envInt("RATE_LIMIT_BURST", 120),
		AuditorURL:                os.Getenv("AUDITOR_URL"),
		AuditorModel:              env("AUDITOR_MODEL", "http-auditor"),
		AuditorTimeoutMS:          envInt("AUDITOR_TIMEOUT_MS", 350),
		AuditorConcurrency:        envInt("AUDITOR_CONCURRENCY", 8),
		EventQueueSize:            envInt("AUDIT_EVENT_QUEUE_SIZE", 1000),
		APIKeyPepper:              os.Getenv("GATEWAY_API_KEY_PEPPER"),
		SSEAuditWindowBytes:       envInt("SSE_AUDIT_WINDOW_BYTES", 16<<10),
		SSEMaxEventBytes:          envInt("SSE_MAX_EVENT_BYTES", 256<<10),
		HealthProbeIntervalMS:     envInt("HEALTH_PROBE_INTERVAL_MS", 5000),
		HealthProbeTimeoutMS:      envInt("HEALTH_PROBE_TIMEOUT_MS", 750),
		SnapshotRefreshIntervalMS: envInt("SNAPSHOT_REFRESH_INTERVAL_MS", 30000),
	}
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
	if len(c.APIKeyPepper) < 32 {
		return fmt.Errorf("GATEWAY_API_KEY_PEPPER must be at least 32 bytes")
	}
	if c.PostgresURL == "" {
		return fmt.Errorf("POSTGRES_URL is required for gateway API key authentication")
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

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func envBool(key string, fallback bool) bool {
	value, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return fallback
	}
	return value
}
