package crypto

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"idp-server/internal/infrastructure/persistence"
)

type rotationRepository interface {
	ListCurrent(ctx context.Context) ([]persistence.JWKKeyRecord, error)
	CreateActiveKey(ctx context.Context, record persistence.JWKKeyRecord, retiresExistingAt time.Time) error
}

type RotationConfig struct {
	WorkingDir    string
	StorageDir    string
	KeyBits       int
	CheckInterval time.Duration
	RotateBefore  time.Duration
	RetireAfter   time.Duration
	KIDPrefix     string
}

type ManualRotateResult struct {
	PreviousKID string
	ActiveKID   string
	RotatedAt   time.Time
	RotatesAt   *time.Time
}

func EnsureKeyManager(ctx context.Context, repo rotationRepository, cfg RotationConfig) (*KeyManager, error) {
	if err := ensureRotation(ctx, repo, cfg); err != nil {
		return nil, err
	}
	return LoadKeyManagerFromRepository(ctx, repo, cfg.WorkingDir)
}

func StartRotationLoop(repo rotationRepository, manager *KeyManager, cfg RotationConfig) {
	if repo == nil || manager == nil || cfg.CheckInterval <= 0 {
		return
	}

	go func() {
		ticker := time.NewTicker(cfg.CheckInterval)
		defer ticker.Stop()

		for range ticker.C {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := ensureRotation(ctx, repo, cfg); err == nil {
				if refreshed, loadErr := LoadKeyManagerFromRepository(ctx, repo, cfg.WorkingDir); loadErr == nil {
					manager.ReplaceWith(refreshed)
				}
			}
			cancel()
		}
	}()
}

func ensureRotation(ctx context.Context, repo rotationRepository, cfg RotationConfig) error {
	_, err := rotateKey(ctx, repo, cfg, false)
	return err
}

func RotateSigningKeyNow(
	ctx context.Context,
	repo interface {
		ListCurrent(ctx context.Context) ([]persistence.JWKKeyRecord, error)
		CreateActiveKey(ctx context.Context, record persistence.JWKKeyRecord, retiresExistingAt time.Time) error
	},
	manager *KeyManager,
	cfg RotationConfig,
) (*ManualRotateResult, error) {
	if repo == nil {
		return nil, fmt.Errorf("rotation repository is required")
	}
	previousRecords, err := repo.ListCurrent(ctx)
	if err != nil {
		return nil, err
	}
	var previousKID string
	if previous := findActiveKey(previousRecords); previous != nil {
		previousKID = previous.KID
	}
	rotatedAt := time.Now().UTC()
	if _, err := rotateKey(ctx, repo, cfg, true); err != nil {
		return nil, err
	}
	if manager != nil {
		refreshed, err := LoadKeyManagerFromRepository(ctx, repo, cfg.WorkingDir)
		if err != nil {
			return nil, err
		}
		manager.ReplaceWith(refreshed)
	}
	currentRecords, err := repo.ListCurrent(ctx)
	if err != nil {
		return nil, err
	}
	active := findActiveKey(currentRecords)
	if active == nil {
		return nil, fmt.Errorf("no active signing key")
	}
	return &ManualRotateResult{
		PreviousKID: previousKID,
		ActiveKID:   active.KID,
		RotatedAt:   rotatedAt,
		RotatesAt:   active.RotatesAt,
	}, nil
}

func rotateKey(ctx context.Context, repo rotationRepository, cfg RotationConfig, force bool) (bool, error) {
	if repo == nil {
		return false, fmt.Errorf("rotation repository is required")
	}
	if cfg.KeyBits <= 0 {
		cfg.KeyBits = 2048
	}
	if cfg.RotateBefore <= 0 {
		cfg.RotateBefore = 24 * time.Hour
	}
	if cfg.RetireAfter <= 0 {
		cfg.RetireAfter = 24 * time.Hour
	}
	if strings.TrimSpace(cfg.KIDPrefix) == "" {
		cfg.KIDPrefix = "kid"
	}

	records, err := repo.ListCurrent(ctx)
	if err != nil {
		return false, err
	}

	now := time.Now().UTC()
	active := findActiveKey(records)
	if !force && active != nil && active.RotatesAt != nil && active.RotatesAt.After(now.Add(cfg.RotateBefore)) {
		return false, nil
	}
	if !force && active != nil && active.RotatesAt == nil {
		return false, nil
	}

	newKey, err := rsa.GenerateKey(rand.Reader, cfg.KeyBits)
	if err != nil {
		return false, fmt.Errorf("generate signing key: %w", err)
	}

	kid := fmt.Sprintf("%s-%s", strings.TrimSpace(cfg.KIDPrefix), now.Format("20060102T150405Z"))
	privateKeyRef, err := writePrivateKey(cfg, kid, newKey)
	if err != nil {
		return false, err
	}

	publicJWK, err := buildPublicJWKJSON(kid, &newKey.PublicKey, DefaultJWTAlg, DefaultKeyUse)
	if err != nil {
		return false, err
	}

	record := persistence.JWKKeyRecord{
		KID:           kid,
		KTY:           "RSA",
		Alg:           DefaultJWTAlg,
		UseType:       DefaultKeyUse,
		PublicJWKJSON: publicJWK,
		PrivateKeyRef: privateKeyRef,
		IsActive:      true,
		CreatedAt:     now,
		RotatesAt:     ptrTime(now.Add(90 * 24 * time.Hour)),
	}

	if err := repo.CreateActiveKey(ctx, record, now.Add(cfg.RetireAfter)); err != nil {
		return false, err
	}
	return true, nil
}

func findActiveKey(records []persistence.JWKKeyRecord) *persistence.JWKKeyRecord {
	for i := range records {
		if records[i].IsActive {
			return &records[i]
		}
	}
	return nil
}

func writePrivateKey(cfg RotationConfig, kid string, privateKey *rsa.PrivateKey) (string, error) {
	dir := strings.TrimSpace(cfg.StorageDir)
	if dir == "" {
		dir = "scripts/dev_keys"
	}
	if !filepath.IsAbs(dir) {
		dir = filepath.Join(cfg.WorkingDir, dir)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create key dir: %w", err)
	}

	path := filepath.Join(dir, kid+".pem")
	encoded, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: encoded}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	relative, err := filepath.Rel(cfg.WorkingDir, path)
	if err != nil {
		return "file://" + path, nil
	}
	return "file://" + filepath.ToSlash(relative), nil
}

func buildPublicJWKJSON(kid string, publicKey *rsa.PublicKey, alg, use string) (string, error) {
	jwk := JSONWebKey{
		Kty: "RSA",
		Kid: kid,
		Use: use,
		Alg: alg,
		N:   jwtEncoding.EncodeToString(publicKey.N.Bytes()),
		E:   jwtEncoding.EncodeToString(bigEndianExponentBytes(publicKey.E)),
	}
	encoded, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(encoded), nil
}

func ptrTime(value time.Time) *time.Time {
	return &value
}
