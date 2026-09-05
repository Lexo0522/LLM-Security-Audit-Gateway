package crypto

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreatePersistsKeyAndDecryptsAcrossReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys", "encryption.key")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := first.Encrypt([]byte("upstream-secret"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := second.Decrypt(ciphertext)
	if err != nil || string(plaintext) != "upstream-secret" {
		t.Fatalf("plaintext=%q err=%v", plaintext, err)
	}
	if bytes.Equal(ciphertext, []byte("upstream-secret")) {
		t.Fatal("ciphertext must not equal plaintext")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0077 != 0 {
			t.Fatalf("key mode=%o must not be group/world accessible", info.Mode().Perm())
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if parent.Mode().Perm()&0077 != 0 {
			t.Fatalf("key directory mode=%o must not be group/world accessible", parent.Mode().Perm())
		}
	}
}

func TestLoadOrCreateRejectsInvalidPersistedKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "encryption.key")
	if err := os.WriteFile(path, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(path); err == nil {
		t.Fatal("invalid persisted key must be rejected")
	}
}
