// Package keys owns the identity provider's RSA signing keys.
//
// One key is active (signs new tokens). After a rotation the previous key
// stays published in the JWKS for a grace period, so tokens it already
// signed keep verifying until they expire; then it is dropped.
package keys

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"sync"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/jwt"
)

type entry struct {
	kid      string
	priv     *rsa.PrivateKey
	retireAt time.Time // zero while active
}

type Manager struct {
	mu      sync.RWMutex
	active  *entry
	retired []*entry
	grace   time.Duration
	bits    int
	now     func() time.Time
}

// New creates a manager with a fresh active key. grace should be at least
// the lifetime of the longest token the key signs.
func New(bits int, grace time.Duration) (*Manager, error) {
	m := &Manager{grace: grace, bits: bits, now: time.Now}
	e, err := newEntry(bits)
	if err != nil {
		return nil, err
	}
	m.active = e
	return m, nil
}

// SetClock is for tests.
func (m *Manager) SetClock(now func() time.Time) {
	m.mu.Lock()
	m.now = now
	m.mu.Unlock()
}

func newEntry(bits int) (*entry, error) {
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &entry{kid: Thumbprint(&k.PublicKey), priv: k}, nil
}

// Thumbprint gives a stable kid derived from the public key itself.
func Thumbprint(pub *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(pub)
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:12])
}

// Sign signs with whatever key is active right now.
func (m *Manager) Sign(c jwt.Claims) (string, error) {
	m.mu.RLock()
	e := m.active
	m.mu.RUnlock()
	return jwt.Sign(c, e.priv, e.kid)
}

func (m *Manager) ActiveKID() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.active.kid
}

// Rotate makes a new active key. The key is generated outside the lock so
// signing never waits on RSA key generation.
func (m *Manager) Rotate() (string, error) {
	fresh, err := newEntry(m.bits)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.active
	old.retireAt = m.now().Add(m.grace)
	m.retired = append(m.retired, old)
	m.active = fresh
	m.pruneLocked()
	return fresh.kid, nil
}

func (m *Manager) pruneLocked() {
	now := m.now()
	kept := m.retired[:0]
	for _, e := range m.retired {
		if now.Before(e.retireAt) {
			kept = append(kept, e)
		}
	}
	m.retired = kept
}

var ErrUnknownKey = jwt.ErrUnknownKey

// PublicKey implements jwt.KeyFunc for in-process verification.
func (m *Manager) PublicKey(kid string) (*rsa.PublicKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	if m.active.kid == kid {
		return &m.active.priv.PublicKey, nil
	}
	for _, e := range m.retired {
		if e.kid == kid {
			return &e.priv.PublicKey, nil
		}
	}
	return nil, ErrUnknownKey
}

// JWK is the public part of one key, as published in /jwks.json (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func toJWK(e *entry) JWK {
	pub := e.priv.PublicKey
	return JWK{
		Kty: "RSA", Use: "sig", Alg: "RS256", Kid: e.kid,
		N: base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// Set returns the active key plus any retiring keys still inside their grace period.
func (m *Manager) Set() JWKS {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.pruneLocked()
	out := JWKS{Keys: []JWK{toJWK(m.active)}}
	for _, e := range m.retired {
		out.Keys = append(out.Keys, toJWK(e))
	}
	return out
}

// RunRotation rotates every interval until ctx is cancelled.
func (m *Manager) RunRotation(ctx context.Context, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := m.Rotate(); err != nil && onErr != nil {
				onErr(err)
			}
		}
	}
}

// ParseJWK turns a published JWK back into an RSA public key and refuses
// anything that isn't an RS256 signing key of a sane size.
func ParseJWK(k JWK) (*rsa.PublicKey, error) {
	if k.Kty != "RSA" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
		return nil, errors.New("jwk: not an RS256 signing key")
	}
	n, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, errors.New("jwk: bad modulus")
	}
	e, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil || len(e) == 0 || len(e) > 4 {
		return nil, errors.New("jwk: bad exponent")
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < 2048 {
		return nil, errors.New("jwk: key shorter than 2048 bits")
	}
	if pub.E < 3 || pub.E%2 == 0 {
		return nil, errors.New("jwk: bad exponent")
	}
	return pub, nil
}
