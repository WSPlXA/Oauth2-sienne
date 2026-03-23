package crypto

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"

	"idp-server/internal/infrastructure/persistence"
)

type signingKeySource interface {
	ListCurrent(ctx context.Context) ([]persistence.JWKKeyRecord, error)
}

type jwkDocument struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func LoadKeyManagerFromRepository(ctx context.Context, source signingKeySource, workingDir string) (*KeyManager, error) {
	if source == nil {
		return nil, fmt.Errorf("signing key source is required")
	}

	records, err := source.ListCurrent(ctx)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("no signing keys configured")
	}

	manager := NewKeyManager()
	activePrivateLoaded := false

	for _, record := range records {
		publicKey, err := parseRSAPublicJWK(record.PublicJWKJSON)
		if err != nil {
			return nil, fmt.Errorf("parse public jwk for kid %s: %w", record.KID, err)
		}
		if err := manager.AddRSAPublicKey(record.KID, publicKey, record.Alg, record.UseType); err != nil {
			return nil, err
		}

		if strings.TrimSpace(record.PrivateKeyRef) == "" {
			continue
		}

		privateKey, err := loadRSAPrivateKey(record.PrivateKeyRef, workingDir)
		if err != nil {
			if record.IsActive {
				return nil, fmt.Errorf("load active private key for kid %s: %w", record.KID, err)
			}
			continue
		}
		if err := manager.AddRSAKey(record.KID, privateKey, record.Alg, record.UseType, record.IsActive); err != nil {
			return nil, err
		}
		if record.IsActive {
			activePrivateLoaded = true
		}
	}

	if !activePrivateLoaded {
		return nil, fmt.Errorf("no active signing private key loaded")
	}

	return manager, nil
}

func parseRSAPublicJWK(raw string) (*rsa.PublicKey, error) {
	var jwk jwkDocument
	if err := json.Unmarshal([]byte(raw), &jwk); err != nil {
		return nil, err
	}
	if strings.ToUpper(strings.TrimSpace(jwk.Kty)) != "RSA" {
		return nil, fmt.Errorf("unsupported jwk kty %q", jwk.Kty)
	}

	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}
	if len(exponentBytes) == 0 {
		return nil, fmt.Errorf("missing exponent")
	}

	exponent := 0
	for _, b := range exponentBytes {
		exponent = (exponent << 8) | int(b)
	}
	if exponent == 0 {
		return nil, fmt.Errorf("invalid exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(modulusBytes),
		E: exponent,
	}, nil
}

func loadRSAPrivateKey(ref, workingDir string) (*rsa.PrivateKey, error) {
	content, err := resolvePrivateKeyRef(ref, workingDir)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("invalid pem content")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	privateKeyAny, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	privateKey, ok := privateKeyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not rsa")
	}
	return privateKey, nil
}

func resolvePrivateKeyRef(ref, workingDir string) ([]byte, error) {
	ref = strings.TrimSpace(ref)
	switch {
	case strings.HasPrefix(ref, "file://"):
		path := strings.TrimPrefix(ref, "file://")
		if !filepath.IsAbs(path) {
			path = filepath.Join(workingDir, path)
		}
		return os.ReadFile(path)
	case strings.HasPrefix(ref, "env://"):
		envName := strings.TrimPrefix(ref, "env://")
		value := os.Getenv(envName)
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("environment variable %s is empty", envName)
		}
		return []byte(value), nil
	case strings.HasPrefix(ref, "vault://"):
		envName := refToEnvName("vault", strings.TrimPrefix(ref, "vault://"))
		value := os.Getenv(envName)
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("vault reference %s is not mapped in %s", ref, envName)
		}
		return []byte(value), nil
	case strings.HasPrefix(ref, "kms://"):
		envName := refToEnvName("kms", strings.TrimPrefix(ref, "kms://"))
		value := os.Getenv(envName)
		if strings.TrimSpace(value) == "" {
			return nil, fmt.Errorf("kms reference %s is not mapped in %s", ref, envName)
		}
		return []byte(value), nil
	default:
		path := ref
		if !filepath.IsAbs(path) {
			path = filepath.Join(workingDir, path)
		}
		return os.ReadFile(path)
	}
}

func refToEnvName(prefix, ref string) string {
	ref = strings.ToUpper(strings.TrimSpace(ref))
	replacer := strings.NewReplacer("/", "_", "-", "_", ".", "_", ":", "_")
	return strings.ToUpper(prefix) + "_" + replacer.Replace(ref)
}
