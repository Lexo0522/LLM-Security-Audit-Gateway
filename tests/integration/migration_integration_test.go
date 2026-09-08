//go:build integration

package integration

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/example/ai-audit-gateway/internal/storage"
)

func TestMigrationRejectsLegacySchema(t *testing.T) {
	if os.Getenv("MIGRATION_REHEARSAL_LEGACY") != "1" {
		t.Skip("legacy schema rehearsal is opt-in")
	}
	repo, err := storage.Open(context.Background(), os.Getenv("POSTGRES_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	err = repo.Migrate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unsupported existing database schema") {
		t.Fatalf("legacy schema migration error=%v", err)
	}
}
