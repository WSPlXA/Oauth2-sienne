package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"strings"
)

const secretEncPrefix = "enc:v1:"

type SecretCodec struct {
	aead cipher.AEAD
}

func NewSecretCodec(keyMaterial string) (*SecretCodec, error) {
	key, err := parseSecretKey(strings.TrimSpace(keyMaterial))
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create aes cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm cipher: %w", err)
	}
	return &SecretCodec{aead: aead}, nil
}

func (c *SecretCodec) Encrypt(plaintext string) (string, error) {
	plaintext = strings.TrimSpace(plaintext)
	if plaintext == "" {
		return "", nil
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext := c.aead.Seal(nil, nonce, []byte(plaintext), nil)
	payload := make([]byte, 0, len(nonce)+len(ciphertext))
	payload = append(payload, nonce...)
	payload = append(payload, ciphertext...)
	return secretEncPrefix + base64.RawURLEncoding.EncodeToString(payload), nil
}

func (c *SecretCodec) Decrypt(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if !strings.HasPrefix(value, secretEncPrefix) {
		// Backward compatibility: old plain-text rows.
		return value, nil
	}

	encoded := strings.TrimPrefix(value, secretEncPrefix)
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode encrypted payload: %w", err)
	}
	nonceSize := c.aead.NonceSize()
	if len(payload) <= nonceSize {
		return "", fmt.Errorf("invalid encrypted payload length")
	}

	plaintext, err := c.aead.Open(nil, payload[:nonceSize], payload[nonceSize:], nil)
	if err != nil {
		return "", fmt.Errorf("decrypt payload: %w", err)
	}
	return string(plaintext), nil
}

func parseSecretKey(keyMaterial string) ([]byte, error) {
	if keyMaterial == "" {
		return nil, fmt.Errorf("empty secret encryption key")
	}

	if strings.HasPrefix(keyMaterial, "base64:") {
		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(keyMaterial, "base64:"))
		if err != nil {
			return nil, fmt.Errorf("decode base64 key: %w", err)
		}
		if err := validateAESKeySize(len(decoded)); err != nil {
			return nil, err
		}
		return decoded, nil
	}

	if decoded, err := base64.StdEncoding.DecodeString(keyMaterial); err == nil && isValidAESKeySize(len(decoded)) {
		return decoded, nil
	}

	raw := []byte(keyMaterial)
	if err := validateAESKeySize(len(raw)); err != nil {
		return nil, err
	}
	return raw, nil
}

func isValidAESKeySize(size int) bool {
	return size == 16 || size == 24 || size == 32
}

func validateAESKeySize(size int) error {
	if !isValidAESKeySize(size) {
		return fmt.Errorf("invalid key length %d (must be 16/24/32 bytes)", size)
	}
	return nil
}
