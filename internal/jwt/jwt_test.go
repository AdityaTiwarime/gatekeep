package jwt

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var (
	key, _   = rsa.GenerateKey(rand.Reader, 2048)
	other, _ = rsa.GenerateKey(rand.Reader, 2048)
	t0       = time.Unix(1_800_000_000, 0)
)

func keyFor(kid string) (*rsa.PublicKey, error) {
	if kid == "k1" {
		return &key.PublicKey, nil
	}
	return nil, ErrUnknownKey
}

func claims(mod func(Claims)) Claims {
	c := Claims{"iss": "https://idp", "aud": "api", "sub": "alice", "iat": t0.Unix(), "nbf": t0.Unix(), "exp": t0.Add(5 * time.Minute).Unix()}
	if mod != nil {
		mod(c)
	}
	return c
}

func opts(now time.Time) Options {
	return Options{Issuer: "https://idp", Audience: "api", Leeway: 30 * time.Second, Now: func() time.Time { return now }}
}

func mustSign(t *testing.T, c Claims) string {
	t.Helper()
	tok, err := Sign(c, key, "k1")
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func raw(header, payload any, sig string) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return b64.EncodeToString(h) + "." + b64.EncodeToString(p) + "." + sig
}

func TestRoundTrip(t *testing.T) {
	_, c, err := Parse(mustSign(t, claims(nil)), keyFor, opts(t0.Add(time.Minute)))
	if err != nil {
		t.Fatal(err)
	}
	if c.String("sub") != "alice" {
		t.Fatalf("sub = %q", c.String("sub"))
	}
}

func TestRejectsBadTokens(t *testing.T) {
	good := mustSign(t, claims(nil))
	parts := strings.Split(good, ".")

	// Tamper with the payload but keep the original signature.
	forged := claims(func(c Claims) { c["sub"] = "admin" })
	fp, _ := json.Marshal(forged)
	tampered := parts[0] + "." + b64.EncodeToString(fp) + "." + parts[2]

	// HS256 "key confusion": sign with the public key bytes as an HMAC secret.
	pubDER, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
	hsInput := b64.EncodeToString(mustJSON(Header{Alg: "HS256", Kid: "k1"})) + "." + parts[1]
	mac := hmac.New(sha256.New, pubDER)
	mac.Write([]byte(hsInput))
	confused := hsInput + "." + b64.EncodeToString(mac.Sum(nil))

	signedByOther, _ := Sign(claims(nil), other, "k1")

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"empty", "", ErrMalformed},
		{"two parts", parts[0] + "." + parts[1], ErrMalformed},
		{"four parts", good + ".x", ErrMalformed},
		{"empty signature", parts[0] + "." + parts[1] + ".", ErrMalformed},
		{"header not base64", "@@@." + parts[1] + "." + parts[2], ErrMalformed},
		{"header not json", b64.EncodeToString([]byte("{not json")) + "." + parts[1] + "." + parts[2], ErrMalformed},
		{"padded base64 signature", good + "==", ErrMalformed},
		{"oversized", strings.Repeat("a", 9000), ErrMalformed},
		{"alg none", raw(Header{Alg: "none", Kid: "k1"}, claims(nil), "x"), ErrAlgorithm},
		{"alg lowercase", raw(Header{Alg: "rs256", Kid: "k1"}, claims(nil), parts[2]), ErrAlgorithm},
		{"HS256 key confusion", confused, ErrAlgorithm},
		{"missing kid", raw(Header{Alg: "RS256"}, claims(nil), parts[2]), ErrMissingClaim},
		{"unknown kid", raw(Header{Alg: "RS256", Kid: "nope"}, claims(nil), parts[2]), ErrUnknownKey},
		{"tampered payload", tampered, ErrSignature},
		{"signed by another key", signedByOther, ErrSignature},
		{"signature garbage", parts[0] + "." + parts[1] + ".AAAA", ErrSignature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(tc.token, keyFor, opts(t0.Add(time.Minute)))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }

func TestTimeChecksAndClockSkew(t *testing.T) {
	exp := t0.Add(5 * time.Minute)
	cases := []struct {
		name string
		now  time.Time
		c    Claims
		want error
	}{
		{"valid", t0.Add(time.Minute), claims(nil), nil},
		{"expired 10s ago, inside 30s leeway", exp.Add(10 * time.Second), claims(nil), nil},
		{"expired 31s ago, outside leeway", exp.Add(31 * time.Second), claims(nil), ErrExpired},
		{"exactly at exp+leeway", exp.Add(30 * time.Second), claims(nil), ErrExpired},
		{"issuer clock 20s ahead, inside leeway", t0.Add(-20 * time.Second), claims(nil), nil},
		{"issued 2 min in the future", t0.Add(-2 * time.Minute), claims(func(c Claims) { delete(c, "nbf") }), ErrIssuedFuture},
		{"nbf 2 min in the future", t0.Add(-2 * time.Minute), claims(func(c Claims) { delete(c, "iat") }), ErrNotYetValid},
		{"no exp at all", t0, claims(func(c Claims) { delete(c, "exp") }), ErrMissingClaim},
		{"wrong issuer", t0, claims(func(c Claims) { c["iss"] = "https://evil" }), ErrIssuer},
		{"wrong audience", t0, claims(func(c Claims) { c["aud"] = "other-api" }), ErrAudience},
		{"audience list containing ours", t0, claims(func(c Claims) { c["aud"] = []string{"x", "api"} }), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Parse(mustSign(t, tc.c), keyFor, opts(tc.now))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func FuzzParse(f *testing.F) {
	f.Add("a.b.c")
	f.Add(raw(Header{Alg: "RS256", Kid: "k1"}, claims(nil), "AAAA"))
	f.Fuzz(func(t *testing.T, tok string) {
		// Must never panic, and must never accept something we didn't sign.
		if _, _, err := Parse(tok, keyFor, opts(t0)); err == nil {
			t.Fatalf("accepted unsigned input %q", tok)
		}
	})
}
