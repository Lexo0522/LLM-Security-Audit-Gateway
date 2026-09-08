package storage

import (
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"testing/fstest"
)

func TestParseMigrationName(t *testing.T) {
	tests := []struct {
		name    string
		version int64
		wantErr bool
	}{
		{name: "001_core.sql", version: 1},
		{name: "42_add_index.sql", version: 42},
		{name: "0_core.sql", wantErr: true},
		{name: "001-Core.sql", wantErr: true},
		{name: "001.sql", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			version, err := parseMigrationName(test.name)
			if test.wantErr {
				if err == nil {
					t.Fatalf("parseMigrationName(%q) succeeded", test.name)
				}
				return
			}
			if err != nil || version != test.version {
				t.Fatalf("version=%d err=%v", version, err)
			}
		})
	}
}

func TestLoadMigrationsSortsAndNormalizesChecksum(t *testing.T) {
	first, err := loadMigrations(fstest.MapFS{
		"002_second.sql": &fstest.MapFile{Data: []byte("SELECT 2;\r\n")},
		"001_first.sql":  &fstest.MapFile{Data: []byte("SELECT 1;\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 2 || first[0].version != 1 || first[1].version != 2 {
		t.Fatalf("unexpected order: %+v", first)
	}
	second, err := loadMigrations(fstest.MapFS{
		"001_first.sql":  &fstest.MapFile{Data: []byte("SELECT 1;\r\n")},
		"002_second.sql": &fstest.MapFile{Data: []byte("SELECT 2;\n")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(first[0].checksum) != string(second[0].checksum) {
		t.Fatalf("CRLF changed checksum: %s != %s", hex.EncodeToString(first[0].checksum), hex.EncodeToString(second[0].checksum))
	}
	if first[0].sql != "SELECT 1;\n" {
		t.Fatalf("sql was not normalized: %q", first[0].sql)
	}
}

func TestLoadMigrationsRejectsDuplicateVersions(t *testing.T) {
	_, err := loadMigrations(fstest.MapFS{
		"001_first.sql": &fstest.MapFile{Data: []byte("SELECT 1")},
		"01_second.sql": &fstest.MapFile{Data: []byte("SELECT 2")},
	})
	if err == nil {
		t.Fatal("duplicate version was accepted")
	}
}

func TestLoadMigrationsRejectsInvalidEntries(t *testing.T) {
	_, err := loadMigrations(fstest.MapFS{
		"README.txt": &fstest.MapFile{Data: []byte("not SQL")},
	})
	if err == nil {
		t.Fatal("non-migration file was accepted")
	}
}

func TestLoadMigrationsRejectsVersionGaps(t *testing.T) {
	_, err := loadMigrations(fstest.MapFS{
		"001_first.sql": &fstest.MapFile{Data: []byte("SELECT 1")},
		"003_third.sql": &fstest.MapFile{Data: []byte("SELECT 3")},
	})
	if err == nil {
		t.Fatal("version gap was accepted")
	}
}

func TestValidateAppliedMigrations(t *testing.T) {
	migrations := []migration{{version: 1, name: "001_core.sql", checksum: []byte{1}}}
	if err := validateAppliedMigrations(map[int64]appliedMigration{1: {version: 1, name: "001_core.sql", checksum: []byte{1}}}, migrations); err != nil {
		t.Fatal(err)
	}
	if err := validateAppliedMigrations(map[int64]appliedMigration{1: {version: 1, name: "001_core.sql", checksum: []byte{2}}}, migrations); err == nil {
		t.Fatal("checksum drift was accepted")
	}
	if err := validateAppliedMigrations(map[int64]appliedMigration{2: {version: 2, name: "002_old.sql", checksum: []byte{1}}}, migrations); err == nil {
		t.Fatal("missing migration was accepted")
	}
}

func TestUnsupportedSchemaErrorIsIdentifiable(t *testing.T) {
	err := fmt.Errorf("%w: details", errUnsupportedSchema)
	if !errors.Is(err, errUnsupportedSchema) {
		t.Fatal("unsupported schema error lost its sentinel")
	}
}
