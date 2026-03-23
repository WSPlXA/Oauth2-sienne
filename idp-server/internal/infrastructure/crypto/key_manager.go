package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"sort"
	"sync"

	keydomain "idp-server/internal/domain/key"
)

const (
	DefaultJWTAlg = "RS256"
	DefaultKeyUse = "sig"
)

type managedKey struct {
	meta       keydomain.Model
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

type KeyManager struct {
	mu        sync.RWMutex
	activeKID string
	keys      map[string]*managedKey
}

type JSONWebKey struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

func NewKeyManager() *KeyManager {
	return &KeyManager{
		keys: make(map[string]*managedKey),
	}
}

func NewGeneratedRSAKeyManager(kid string, bits int) (*KeyManager, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("generate rsa key: %w", err)
	}

	manager := NewKeyManager()
	if err := manager.AddRSAKey(kid, privateKey, DefaultJWTAlg, DefaultKeyUse, true); err != nil {
		return nil, err
	}

	return manager, nil
}

func (m *KeyManager) AddRSAKey(kid string, privateKey *rsa.PrivateKey, alg, use string, makeActive bool) error {
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if privateKey == nil {
		return fmt.Errorf("private key is required")
	}
	if alg == "" {
		alg = DefaultJWTAlg
	}
	if use == "" {
		use = DefaultKeyUse
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.keys[kid] = &managedKey{
		meta: keydomain.Model{
			KID: kid,
			Alg: alg,
			Use: use,
		},
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
	}

	if makeActive || m.activeKID == "" {
		m.activeKID = kid
	}

	return nil
}

func (m *KeyManager) AddRSAPublicKey(kid string, publicKey *rsa.PublicKey, alg, use string) error {
	if kid == "" {
		return fmt.Errorf("kid is required")
	}
	if publicKey == nil {
		return fmt.Errorf("public key is required")
	}
	if alg == "" {
		alg = DefaultJWTAlg
	}
	if use == "" {
		use = DefaultKeyUse
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	current := m.keys[kid]
	if current == nil {
		m.keys[kid] = &managedKey{
			meta: keydomain.Model{
				KID: kid,
				Alg: alg,
				Use: use,
			},
			publicKey: publicKey,
		}
		return nil
	}

	current.meta = keydomain.Model{
		KID: kid,
		Alg: alg,
		Use: use,
	}
	current.publicKey = publicKey
	return nil
}

func (m *KeyManager) ActiveSigningKey() (keydomain.Model, *rsa.PrivateKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.activeKID == "" {
		return keydomain.Model{}, nil, fmt.Errorf("no active signing key")
	}

	record, ok := m.keys[m.activeKID]
	if !ok || record.privateKey == nil {
		return keydomain.Model{}, nil, fmt.Errorf("active signing key not found")
	}

	return record.meta, record.privateKey, nil
}

func (m *KeyManager) PublicKeyByKID(kid string) (keydomain.Model, *rsa.PublicKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	record, ok := m.keys[kid]
	if !ok || record.publicKey == nil {
		return keydomain.Model{}, nil, fmt.Errorf("public key not found for kid %q", kid)
	}

	return record.meta, record.publicKey, nil
}

func (m *KeyManager) PublicJWKS() []JSONWebKey {
	m.mu.RLock()
	defer m.mu.RUnlock()

	kids := make([]string, 0, len(m.keys))
	for kid := range m.keys {
		kids = append(kids, kid)
	}
	sort.Strings(kids)

	keys := make([]JSONWebKey, 0, len(kids))
	for _, kid := range kids {
		record := m.keys[kid]
		if record == nil || record.publicKey == nil {
			continue
		}

		keys = append(keys, JSONWebKey{
			Kty: "RSA",
			Kid: record.meta.KID,
			Use: record.meta.Use,
			Alg: record.meta.Alg,
			N:   base64.RawURLEncoding.EncodeToString(record.publicKey.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(bigEndianExponentBytes(record.publicKey.E)),
		})
	}

	return keys
}

func (m *KeyManager) ReplaceWith(other *KeyManager) {
	if other == nil {
		return
	}

	other.mu.RLock()
	defer other.mu.RUnlock()

	cloned := make(map[string]*managedKey, len(other.keys))
	for kid, record := range other.keys {
		if record == nil {
			continue
		}
		cloned[kid] = &managedKey{
			meta:       record.meta,
			privateKey: record.privateKey,
			publicKey:  record.publicKey,
		}
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.activeKID = other.activeKID
	m.keys = cloned
}

func bigEndianExponentBytes(value int) []byte {
	if value == 0 {
		return []byte{0}
	}

	var out []byte
	for value > 0 {
		out = append([]byte{byte(value & 0xff)}, out...)
		value >>= 8
	}
	return out
}
