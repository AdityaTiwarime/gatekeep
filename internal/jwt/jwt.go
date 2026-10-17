// Package jwt signs and verifies RS256 JSON Web Tokens.
//
// It is deliberately strict: only RS256 is accepted (no "none", no HS256 key
// confusion), the header must carry a kid, exp is mandatory and every time
// check allows a small, configurable clock-skew leeway.
package jwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrMalformed    = errors.New("malformed token")
	ErrAlgorithm    = errors.New("unexpected signing algorithm")
	ErrUnknownKey   = errors.New("unknown signing key")
	ErrSignature    = errors.New("signature verification failed")
	ErrExpired      = errors.New("token expired")
	ErrNotYetValid  = errors.New("token not valid yet")
	ErrIssuedFuture = errors.New("token issued in the future")
	ErrIssuer       = errors.New("unexpected issuer")
	ErrAudience     = errors.New("unexpected audience")
	ErrMissingClaim = errors.New("missing required claim")
)

// maxTokenSize stops someone from making us base64-decode megabytes per request.
const maxTokenSize = 8 << 10

var b64 = base64.RawURLEncoding

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid"`
}

// Claims is kept as a map so extra claims (roles, nonce, sid...) pass through untouched.
type Claims map[string]any

func (c Claims) String(name string) string {
	s, _ := c[name].(string)
	return s
}

// Time reads a NumericDate claim. JSON numbers decode as float64.
func (c Claims) Time(name string) (time.Time, bool) {
	switch v := c[name].(type) {
	case float64:
		return time.Unix(int64(v), 0), true
	case int64:
		return time.Unix(v, 0), true
	case int:
		return time.Unix(int64(v), 0), true
	}
	return time.Time{}, false
}

func (c Claims) Strings(name string) []string {
	switch v := c[name].(type) {
	case string:
		return []string{v}
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, x := range v {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// Sign returns a compact RS256 JWS.
func Sign(claims Claims, key *rsa.PrivateKey, kid string) (string, error) {
	h, err := json.Marshal(Header{Alg: "RS256", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signingInput := b64.EncodeToString(h) + "." + b64.EncodeToString(p)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(nil, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// KeyFunc returns the public key for a kid, or ErrUnknownKey.
type KeyFunc func(kid string) (*rsa.PublicKey, error)

type Options struct {
	Issuer   string
	Audience string        // empty = don't check
	Leeway   time.Duration // allowed clock skew, applied to exp/nbf/iat
	Now      func() time.Time
}

// Parse verifies the signature first and only then looks at the claims,
// so nothing from an unverified payload is ever trusted.
func Parse(token string, keyFor KeyFunc, opt Options) (Header, Claims, error) {
	var hdr Header
	if len(token) == 0 || len(token) > maxTokenSize {
		return hdr, nil, ErrMalformed
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return hdr, nil, ErrMalformed
	}

	rawHdr, err := b64.DecodeString(parts[0])
	if err != nil {
		return hdr, nil, fmt.Errorf("%w: header encoding", ErrMalformed)
	}
	if err := json.Unmarshal(rawHdr, &hdr); err != nil {
		return hdr, nil, fmt.Errorf("%w: header json", ErrMalformed)
	}
	// Pin the algorithm instead of trusting the header: blocks "none" and
	// the classic RS256 -> HS256 key-confusion trick.
	if hdr.Alg != "RS256" {
		return hdr, nil, fmt.Errorf("%w: %q", ErrAlgorithm, hdr.Alg)
	}
	if hdr.Kid == "" {
		return hdr, nil, fmt.Errorf("%w: kid", ErrMissingClaim)
	}

	pub, err := keyFor(hdr.Kid)
	if err != nil {
		return hdr, nil, err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return hdr, nil, fmt.Errorf("%w: signature encoding", ErrMalformed)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return hdr, nil, ErrSignature
	}

	rawClaims, err := b64.DecodeString(parts[1])
	if err != nil {
		return hdr, nil, fmt.Errorf("%w: payload encoding", ErrMalformed)
	}
	var claims Claims
	if err := json.Unmarshal(rawClaims, &claims); err != nil {
		return hdr, nil, fmt.Errorf("%w: payload json", ErrMalformed)
	}
	return hdr, claims, checkClaims(claims, opt)
}

func checkClaims(c Claims, opt Options) error {
	now := time.Now()
	if opt.Now != nil {
		now = opt.Now()
	}

	exp, ok := c.Time("exp")
	if !ok {
		return fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if !now.Before(exp.Add(opt.Leeway)) {
		return ErrExpired
	}
	if nbf, ok := c.Time("nbf"); ok && now.Add(opt.Leeway).Before(nbf) {
		return ErrNotYetValid
	}
	if iat, ok := c.Time("iat"); ok && now.Add(opt.Leeway).Before(iat) {
		return ErrIssuedFuture
	}
	if opt.Issuer != "" && c.String("iss") != opt.Issuer {
		return ErrIssuer
	}
	if opt.Audience != "" {
		for _, a := range c.Strings("aud") {
			if a == opt.Audience {
				return nil
			}
		}
		return ErrAudience
	}
	return nil
}
