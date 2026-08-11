package config

import (
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr       string
	AdminAddr        string
	UpstreamURL      string
	UpstreamAPIKey   string
	MaxBodyBytes     int
	MaxResponseBytes int
	RequestTimeoutMS int
	AuditEnabled     bool
	FailClosed       bool
}

func Load() Config {
	return Config{
		ListenAddr:       env("GATEWAY_LISTEN_ADDR", ":8080"),
		AdminAddr:        env("GATEWAY_ADMIN_ADDR", ":8081"),
		UpstreamURL:      strings.TrimRight(env("NEWAPI_BASE_URL", "http://newapi:3000"), "/"),
		UpstreamAPIKey:   os.Getenv("NEWAPI_API_KEY"),
		MaxBodyBytes:     envInt("MAX_BODY_BYTES", 4<<20),
		MaxResponseBytes: envInt("MAX_RESPONSE_BYTES", 16<<20),
		RequestTimeoutMS: envInt("REQUEST_TIMEOUT_MS", 120000),
		AuditEnabled:     envBool("AUDIT_ENABLED", true),
		FailClosed:       envBool("AUDIT_FAIL_CLOSED", false),
	}
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
