package keys

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/jwt"
)

func TestRotationGracePeriod(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	m, err := New(2048, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	m.SetClock(func() time.Time { return now })

	exp := now.Add(5 * time.Minute).Unix()
	oldTok, _ := m.Sign(jwt.Claims{"exp": exp})
	oldKid := m.ActiveKID()

	newKid, err := m.Rotate()
	if err != nil || newKid == oldKid {
		t.Fatalf("rotate: kid %q err %v", newKid, err)
	}
	newTok, _ := m.Sign(jwt.Claims{"exp": exp})

	opt := jwt.Options{Now: func() time.Time { return now }}
	if h, _, err := jwt.Parse(newTok, m.PublicKey, opt); err != nil || h.Kid != newKid {
		t.Fatalf("new token: kid %q err %v", h.Kid, err)
	}
	if _, _, err := jwt.Parse(oldTok, m.PublicKey, opt); err != nil {
		t.Fatalf("token signed before rotation must still verify during grace: %v", err)
	}
	if n := len(m.Set().Keys); n != 2 {
		t.Fatalf("JWKS should publish active + retiring key, got %d", n)
	}

	now = now.Add(11 * time.Minute) // grace over
	if n := len(m.Set().Keys); n != 1 {
		t.Fatalf("retired key should be dropped after grace, got %d keys", n)
	}
	if _, err := m.PublicKey(oldKid); !errors.Is(err, ErrUnknownKey) {
		t.Fatalf("old kid should be unknown after grace, got %v", err)
	}
}

func TestJWKRoundTrip(t *testing.T) {
	m, _ := New(2048, time.Minute)
	jwk := m.Set().Keys[0]
	pub, err := ParseJWK(jwk)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := m.PublicKey(jwk.Kid)
	if !pub.Equal(want) {
		t.Fatal("JWK does not round-trip to the same public key")
	}
	if Thumbprint(pub) != jwk.Kid {
		t.Fatal("kid should be the key's thumbprint")
	}

	bad := jwk
	bad.Kty = "EC"
	if _, err := ParseJWK(bad); err == nil {
		t.Fatal("non-RSA key accepted")
	}
	bad = jwk
	bad.Alg = "HS256"
	if _, err := ParseJWK(bad); err == nil {
		t.Fatal("HS256 key accepted")
	}
	small, _ := New(1024, time.Minute)
	if _, err := ParseJWK(small.Set().Keys[0]); err == nil {
		t.Fatal("1024-bit key accepted")
	}
}

// Run with -race: signing and verifying while keys rotate underneath.
func TestConcurrentSignVerifyDuringRotation(t *testing.T) {
	m, _ := New(2048, time.Hour)
	exp := time.Now().Add(time.Minute).Unix()
	var wg sync.WaitGroup
	errs := make(chan error, 200)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				tok, err := m.Sign(jwt.Claims{"exp": exp})
				if err == nil {
					_, _, err = jwt.Parse(tok, m.PublicKey, jwt.Options{})
				}
				if err != nil {
					errs <- err
				}
				_ = m.Set()
			}
		}()
	}
	for i := 0; i < 3; i++ {
		if _, err := m.Rotate(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
}
