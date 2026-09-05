// Package crypto provides the gateway's small, file-backed encryption primitive.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const KeySize = 32

var (
	ErrInvalidKey        = errors.New("invalid encryption key")
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// Key is an AES-256-GCM key. It is safe for concurrent use.
type Key struct{ aead cipher.AEAD }

// New validates a raw 32-byte key and constructs an encryptor.
func New(raw []byte) (*Key, error) {
	if len(raw) != KeySize {
		return nil, fmt.Errorf("%w: need %d bytes", ErrInvalidKey, KeySize)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("create AES cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	return &Key{aead: aead}, nil
}

// Encrypt returns nonce || ciphertext. A fresh random nonce is generated for
// every call; callers may safely persist the returned bytes as-is.
func (k *Key) Encrypt(plaintext []byte) ([]byte, error) {
	if k == nil || k.aead == nil {
		return nil, ErrInvalidKey
	}
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("generate encryption nonce: %w", err)
	}
	return k.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt authenticates and decrypts a nonce || ciphertext value.
func (k *Key) Decrypt(ciphertext []byte) ([]byte, error) {
	if k == nil || k.aead == nil {
		return nil, ErrInvalidKey
	}
	if len(ciphertext) < k.aead.NonceSize()+k.aead.Overhead() {
		return nil, ErrInvalidCiphertext
	}
	nonceSize := k.aead.NonceSize()
	plaintext, err := k.aead.Open(nil, ciphertext[:nonceSize], ciphertext[nonceSize:], nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}
	return plaintext, nil
}

// LoadOrCreate reads a 32-byte service key, creating it with mode 0600 when it
// does not exist. Creation uses an exclusive file and a private parent dir.
func LoadOrCreate(path string) (*Key, error) {
	if path == "" {
		return nil, fmt.Errorf("key path is required")
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is the deployment-configured server key, never request data
	if err == nil {
		if chmodErr := os.Chmod(path, 0600); chmodErr != nil {
			return nil, fmt.Errorf("restrict encryption key permissions: %w", chmodErr)
		}
		return New(data)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read encryption key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("create encryption key directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil { // #nosec G302 -- the key directory must remain private and executable by its owner
		return nil, fmt.Errorf("restrict encryption key directory permissions: %w", err)
	}
	raw := make([]byte, KeySize)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return nil, fmt.Errorf("generate encryption key: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // #nosec G304 -- path is the deployment-configured server key, never request data
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			data, readErr := os.ReadFile(path) // #nosec G304 -- path is the deployment-configured server key, never request data
			if readErr != nil {
				return nil, fmt.Errorf("read concurrently-created encryption key: %w", readErr)
			}
			return New(data)
		}
		return nil, fmt.Errorf("create encryption key: %w", err)
	}
	_, writeErr := file.Write(raw)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		_ = os.Remove(path)
		if writeErr != nil {
			return nil, fmt.Errorf("write encryption key: %w", writeErr)
		}
		return nil, fmt.Errorf("close encryption key: %w", closeErr)
	}
	return New(raw)
}

// EncodeKey is useful for configuration/bootstrap tooling, but does not expose
// key material in normal application paths.
func EncodeKey(raw []byte) (string, error) {
	if len(raw) != KeySize {
		return "", ErrInvalidKey
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// EqualKey compares two raw key values without an early-exit comparison.
func EqualKey(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare(a, b) == 1
}
