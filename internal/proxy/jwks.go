package proxy

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/jwt"
	"github.com/AdityaTiwarime/gatekeep/internal/keys"
)

// JWKSCache keeps the IdP's public keys in memory. On an unknown kid it
// refetches the JWKS (that's how a key rotation is picked up), but at most
// once per minInterval, so a flood of tokens with random kids can't turn
// the proxy into a hammer against the IdP.
type JWKSCache struct {
	url         string
	client      *http.Client
	minInterval time.Duration
	now         func() time.Time

	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchMu   sync.Mutex // one fetch at a time
	lastFetch time.Time

	Fetches atomic.Int64 // exposed for tests and metrics
}

func NewJWKSCache(url string, client *http.Client, minInterval time.Duration) *JWKSCache {
	return &JWKSCache{url: url, client: client, minInterval: minInterval, now: time.Now, keys: map[string]*rsa.PublicKey{}}
}

func (c *JWKSCache) lookup(kid string) *rsa.PublicKey {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.keys[kid]
}

// KeyFor implements jwt.KeyFunc.
func (c *JWKSCache) KeyFor(kid string) (*rsa.PublicKey, error) {
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	if k := c.lookup(kid); k != nil { // someone else fetched while we waited
		return k, nil
	}
	if !c.lastFetch.IsZero() && c.now().Sub(c.lastFetch) < c.minInterval {
		return nil, jwt.ErrUnknownKey
	}
	if err := c.fetchLocked(); err != nil {
		return nil, fmt.Errorf("%w: jwks refresh failed: %v", jwt.ErrUnknownKey, err)
	}
	if k := c.lookup(kid); k != nil {
		return k, nil
	}
	return nil, jwt.ErrUnknownKey
}

// Refresh forces a fetch (used at startup).
func (c *JWKSCache) Refresh() error {
	c.fetchMu.Lock()
	defer c.fetchMu.Unlock()
	return c.fetchLocked()
}

func (c *JWKSCache) fetchLocked() error {
	c.lastFetch = c.now()
	c.Fetches.Add(1)
	resp, err := c.client.Get(c.url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jwks: status %d", resp.StatusCode)
	}
	var set keys.JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&set); err != nil {
		return fmt.Errorf("jwks: %w", err)
	}
	fresh := map[string]*rsa.PublicKey{}
	for _, k := range set.Keys {
		pub, err := keys.ParseJWK(k)
		if err != nil || k.Kid == "" {
			continue // skip keys we can't safely use rather than failing everything
		}
		fresh[k.Kid] = pub
	}
	if len(fresh) == 0 {
		return fmt.Errorf("jwks: no usable keys")
	}
	c.mu.Lock()
	c.keys = fresh // keys removed from the JWKS stop verifying too
	c.mu.Unlock()
	return nil
}
