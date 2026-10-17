package proxy

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/jwt"
	"github.com/AdityaTiwarime/gatekeep/internal/keys"
	"github.com/AdityaTiwarime/gatekeep/internal/pki"
	"github.com/AdityaTiwarime/gatekeep/internal/revoke"
)

// env wires a fake IdP (real JWKS + revocation feed), a backend that echoes
// what it receives, and the proxy in front of it.
type env struct {
	t       *testing.T
	keys    *keys.Manager
	revoked *revoke.List
	idp     *httptest.Server
	proxy   *Proxy
	front   *httptest.Server
	cache   *JWKSCache
	now     time.Time
	mu      sync.Mutex
}

func newEnv(t *testing.T) *env {
	km, _ := keys.New(2048, time.Hour) // fresh per test so rotations don't leak between tests
	e := &env{t: t, keys: km, revoked: revoke.New(), now: time.Now()}

	idpMux := http.NewServeMux()
	idpMux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(km.Set()) })
	idpMux.HandleFunc("/internal/revocations", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer feed-secret" {
			http.Error(w, "no", 403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"revoked": e.revoked.Snapshot()})
	})
	e.idp = httptest.NewServer(idpMux)
	t.Cleanup(e.idp.Close)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"path": r.URL.Path, "user": r.Header.Get("X-Auth-User"), "roles": r.Header.Get("X-Auth-Roles"),
			"authorization": r.Header.Get("Authorization"), "remote_user": r.Header.Get("X-Remote-User"),
			"xff": r.Header.Get("X-Forwarded-For"),
		})
	}))
	t.Cleanup(backend.Close)
	up, _ := url.Parse(backend.URL)

	e.cache = NewJWKSCache(e.idp.URL+"/jwks.json", http.DefaultClient, time.Hour)
	e.cache.now = e.clock
	e.proxy = New(Config{
		Upstream: up, Issuer: "https://idp.example", Audience: "api", Leeway: 30 * time.Second,
		Rules:          []Rule{{Prefix: "/health", Public: true}, {Prefix: "/admin", Role: "admin"}},
		RevocationsURL: e.idp.URL + "/internal/revocations", InternalSecret: "feed-secret",
		HTTPClient: http.DefaultClient, Now: e.clock,
	}, e.cache)
	e.front = httptest.NewServer(e.proxy)
	t.Cleanup(e.front.Close)
	return e
}

func (e *env) clock() time.Time        { e.mu.Lock(); defer e.mu.Unlock(); return e.now }
func (e *env) advance(d time.Duration) { e.mu.Lock(); e.now = e.now.Add(d); e.mu.Unlock() }

func (e *env) token(sub string, roles []string, mod func(jwt.Claims)) string {
	now := e.clock()
	c := jwt.Claims{"iss": "https://idp.example", "aud": "api", "sub": sub, "roles": roles,
		"iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(), "jti": sub + "-" + now.String()}
	if mod != nil {
		mod(c)
	}
	tok, err := e.keys.Sign(c)
	if err != nil {
		e.t.Fatal(err)
	}
	return tok
}

func (e *env) get(path, tok string, hdr map[string]string) (int, map[string]string, http.Header) {
	e.t.Helper()
	req, _ := http.NewRequest("GET", e.front.URL+path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body, resp.Header
}

func TestValidTokenReachesBackendWithIdentity(t *testing.T) {
	e := newEnv(t)
	status, body, _ := e.get("/hello", e.token("alice", []string{"user"}, nil), nil)
	if status != 200 || body["user"] != "alice" || body["roles"] != "user" {
		t.Fatalf("got %d %v", status, body)
	}
	if body["authorization"] != "" {
		t.Fatal("raw token should not be forwarded to the backend by default")
	}
}

func TestSpoofedIdentityHeadersAreStripped(t *testing.T) {
	e := newEnv(t)
	spoof := map[string]string{"X-Auth-User": "bob", "X-Auth-Roles": "admin", "X-Remote-User": "root", "X-Forwarded-For": "1.2.3.4"}

	_, body, _ := e.get("/hello", e.token("alice", []string{"user"}, nil), spoof)
	if body["user"] != "alice" || body["roles"] != "user" || body["remote_user"] != "" {
		t.Fatalf("spoofed headers leaked through: %v", body)
	}
	if strings.HasPrefix(body["xff"], "1.2.3.4") {
		t.Fatalf("client-supplied X-Forwarded-For was trusted: %q", body["xff"])
	}
	// On a public route the spoofed headers must be stripped too.
	_, body, _ = e.get("/health", "", spoof)
	if body["user"] != "" || body["roles"] != "" {
		t.Fatalf("public route passed spoofed identity: %v", body)
	}
}

func TestRejections(t *testing.T) {
	e := newEnv(t)
	good := e.token("alice", []string{"user"}, nil)
	parts := strings.Split(good, ".")

	cases := []struct {
		name   string
		tok    string
		path   string
		status int
		reason string
	}{
		{"no token", "", "/hello", 401, "missing bearer token"},
		{"garbage", "abc", "/hello", 401, "token invalid"},
		{"tampered signature", parts[0] + "." + parts[1] + ".AAAA", "/hello", 401, "token invalid"},
		{"wrong audience", e.token("alice", nil, func(c jwt.Claims) { c["aud"] = "other" }), "/hello", 401, "token invalid"},
		{"wrong issuer", e.token("alice", nil, func(c jwt.Claims) { c["iss"] = "https://evil" }), "/hello", 401, "token invalid"},
		{"expired", e.token("alice", nil, func(c jwt.Claims) { c["exp"] = e.clock().Add(-time.Minute).Unix() }), "/hello", 401, "token expired"},
		{"user on admin route", good, "/admin/users", 403, "requires role admin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, body, h := e.get(tc.path, tc.tok, nil)
			if status != tc.status || body["error_description"] != tc.reason {
				t.Fatalf("got %d %v", status, body)
			}
			if !strings.HasPrefix(h.Get("WWW-Authenticate"), "Bearer") {
				t.Fatalf("missing WWW-Authenticate: %v", h)
			}
		})
	}

	if status, _, _ := e.get("/admin/users", e.token("bob", []string{"user", "admin"}, nil), nil); status != 200 {
		t.Fatalf("admin should reach /admin, got %d", status)
	}
	if status, _, _ := e.get("/health", "", nil); status != 200 {
		t.Fatalf("public route needs no token, got %d", status)
	}
}

func TestClockSkew(t *testing.T) {
	e := newEnv(t)
	tok := e.token("alice", nil, nil)
	e.advance(5*time.Minute + 20*time.Second) // past exp but inside the 30s leeway
	if status, _, _ := e.get("/hello", tok, nil); status != 200 {
		t.Fatalf("inside leeway: %d", status)
	}
	e.advance(15 * time.Second)
	if status, body, _ := e.get("/hello", tok, nil); status != 401 || body["error_description"] != "token expired" {
		t.Fatalf("outside leeway: %d %v", status, body)
	}
}

func TestRevokedTokenBlockedAfterSync(t *testing.T) {
	e := newEnv(t)
	tok := e.token("alice", nil, func(c jwt.Claims) { c["jti"] = "revoke-me" })
	if status, _, _ := e.get("/hello", tok, nil); status != 200 {
		t.Fatal("token should work before revocation")
	}
	e.revoked.Add("revoke-me", e.clock().Add(time.Hour))
	e.proxy.SyncRevocations(context.Background())
	if status, body, _ := e.get("/hello", tok, nil); status != 401 || body["error_description"] != "token revoked" {
		t.Fatalf("revoked token: %d %v", status, body)
	}
}

func TestKeyRotationIsPickedUp(t *testing.T) {
	e := newEnv(t)
	old := e.token("alice", nil, nil)
	if status, _, _ := e.get("/hello", old, nil); status != 200 {
		t.Fatal("first call failed")
	}
	if _, err := e.keys.Rotate(); err != nil {
		t.Fatal(err)
	}
	e.advance(time.Hour + time.Second) // past the cache's minimum refetch interval
	fresh := e.token("alice", nil, nil)
	if status, _, _ := e.get("/hello", fresh, nil); status != 200 {
		t.Fatalf("token from the rotated key rejected: %d", status)
	}
}

func TestUnknownKidFloodIsRateLimited(t *testing.T) {
	e := newEnv(t)
	_ = e.cache.Refresh()
	before := e.cache.Fetches.Load()
	other, _ := keys.New(2048, time.Hour) // attacker's own key
	for i := 0; i < 50; i++ {
		tok, _ := other.Sign(jwt.Claims{"iss": "https://idp.example", "aud": "api", "exp": time.Now().Add(time.Minute).Unix()})
		if status, _, _ := e.get("/hello", tok, nil); status != 401 {
			t.Fatalf("foreign key accepted: %d", status)
		}
	}
	if n := e.cache.Fetches.Load() - before; n > 1 {
		t.Fatalf("50 unknown-kid tokens caused %d JWKS fetches, want at most 1", n)
	}
}

func TestConcurrentRequests(t *testing.T) {
	e := newEnv(t)
	tok := e.token("alice", []string{"user"}, nil)
	var wg sync.WaitGroup
	fail := make(chan int, 100)
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if status, _, _ := e.get("/hello", tok, nil); status != 200 {
				fail <- status
			}
		}()
	}
	wg.Wait()
	close(fail)
	for s := range fail {
		t.Fatalf("concurrent request failed with %d", s)
	}
}

func TestTLSTermination(t *testing.T) {
	e := newEnv(t)
	ca, err := pki.NewCA("test CA", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, err := ca.IssueServer([]string{"127.0.0.1", "localhost"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	srvTLS, err := pki.ServerTLS(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(e.proxy)
	ts.TLS = srvTLS
	ts.StartTLS()
	defer ts.Close()

	trusting, _ := pki.ClientTrusting(ca.PEM)
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: trusting}}
	req, _ := http.NewRequest("GET", ts.URL+"/hello", nil)
	req.Header.Set("Authorization", "Bearer "+e.token("alice", nil, nil))
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("TLS request with trusted CA: %v %v", err, resp)
	}
	if resp.TLS == nil || resp.TLS.Version < tls.VersionTLS12 {
		t.Fatal("expected TLS 1.2+")
	}

	if _, err := http.Get(ts.URL + "/health"); err == nil {
		t.Fatal("client without our CA must not trust the certificate")
	}

	old := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs: trusting.RootCAs, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11,
	}}}
	if _, err := old.Get(ts.URL + "/health"); err == nil {
		t.Fatal("TLS 1.1 handshake must be refused")
	}
}
