// Command seed installs the first managed production audit configuration.
// It is intentionally one-shot: existing global configuration is never changed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/example/ai-audit-gateway/internal/config"
	"github.com/example/ai-audit-gateway/internal/policy"
	"github.com/example/ai-audit-gateway/internal/rule"
	"github.com/example/ai-audit-gateway/internal/storage"
)

type seedConfig struct {
	Rules    []rule.Definition `json:"rules"`
	Policies []policy.Policy   `json:"policies"`
}

func main() {
	path := flag.String("file", "", "path to managed seed JSON")
	flag.Parse()
	if *path == "" {
		fail("-file is required")
	}
	raw, err := os.ReadFile(*path)
	if err != nil {
		fail("read seed file: %v", err)
	}
	var value seedConfig
	if err = json.Unmarshal(raw, &value); err != nil {
		fail("parse seed file: %v", err)
	}
	cfg := config.Load()
	if cfg.PostgresURL == "" {
		fail("POSTGRES_URL is required")
	}
	ctx := context.Background()
	repo, err := storage.Open(ctx, cfg.PostgresURL)
	if err != nil {
		fail("open postgres: %v", err)
	}
	defer repo.Close()
	if err = repo.Migrate(ctx); err != nil {
		fail("migrate postgres: %v", err)
	}
	if err = repo.SeedManagedConfiguration(ctx, value.Rules, value.Policies); err != nil {
		fail("seed managed configuration: %v", err)
	}
	fmt.Println("managed global rules and policies seeded")
}
func fail(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
