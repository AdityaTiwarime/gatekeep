package idp

import (
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/AdityaTiwarime/gatekeep/internal/revoke"
)

const redirect = "https://app.example/cb"

var (
	sharedKeys  *keys.Manager
	sharedUsers []*User
	setupOnce   sync.Once
)

type fixture struct {
	t       *testing.T
	srv     *Server
	http    *httptest.Server
	revoked *revoke.List
	now     time.Time
	mu      sync.Mutex
}

func newFixture(t *testing.T) *fixture {
	setupOnce.Do(func() { // RSA + PBKDF2 are slow; build them once for the whole package
		sharedKeys, _ = keys.New(2048, time.Hour)
		a, _ := NewUser("alice", "correct horse", "Alice", "alice@example.com", "user")
		b, _ := NewUser("bob", "battery staple", "Bob", "bob@example.com", "user", "admin")
		sharedUsers = []*User{a, b}
	})
	f := &fixture{t: t, revoked: revoke.New(), now: time.Now()}
	f.srv = New(Config{
		Issuer: "https://idp.example", APIAudience: "api", InternalSecret: "s3cret",
		AccessTTL: 5 * time.Minute, RefreshTTL: time.Hour, CodeTTL: time.Minute,
		Keys: sharedKeys, Revoked: f.revoked, Now: f.clock,
	}, []*Client{
		{ID: "web", RedirectURIs: []string{redirect}},
		{ID: "svc", Secret: "svc-secret", RedirectURIs: []string{redirect}},
	}, sharedUsers)
	f.http = httptest.NewServer(f.srv.Handler())
	t.Cleanup(f.http.Close)
	return f
}

func (f *fixture) clock() time.Time        { f.mu.Lock(); defer f.mu.Unlock(); return f.now }
func (f *fixture) advance(d time.Duration) { f.mu.Lock(); f.now = f.now.Add(d); f.mu.Unlock() }

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func pkce() (verifier, challenge string) {
	verifier = strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

func (f *fixture) authorize(user, pass string, mod func(url.Values)) *http.Response {
	f.t.Helper()
	_, ch := pkce()
	v := url.Values{
		"client_id": {"web"}, "redirect_uri": {redirect}, "state": {"st"}, "scope": {"openid profile"},
		"nonce": {"n0"}, "code_challenge": {ch}, "username": {user}, "password": {pass},
	}
	if mod != nil {
		mod(v)
	}
	resp, err := noFollow.PostForm(f.http.URL+"/authorize", v)
	if err != nil {
		f.t.Fatal(err)
	}
	return resp
}

func (f *fixture) login(user, pass string) string {
	f.t.Helper()
	resp := f.authorize(user, pass, nil)
	if resp.StatusCode != http.StatusFound {
		f.t.Fatalf("login: status %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("state") != "st" || loc.Query().Get("iss") != "https://idp.example" {
		f.t.Fatalf("redirect missing state/iss: %s", loc)
	}
	return loc.Query().Get("code")
}

func (f *fixture) post(path string, v url.Values) (int, map[string]any) {
	f.t.Helper()
	resp, err := http.PostForm(f.http.URL+path, v)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	var body map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&body)
	return resp.StatusCode, body
}

func (f *fixture) exchange(code string) (int, map[string]any) {
	v, _ := pkce()
	return f.post("/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {"web"}, "code_verifier": {v}})
}

func (f *fixture) refresh(rt string) (int, map[string]any) {
	return f.post("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}, "client_id": {"web"}})
}

func (f *fixture) parse(tok, aud string) jwt.Claims {
	f.t.Helper()
	_, c, err := jwt.Parse(tok, sharedKeys.PublicKey, jwt.Options{Issuer: "https://idp.example", Audience: aud, Now: f.clock})
	if err != nil {
		f.t.Fatalf("token does not verify: %v", err)
	}
	return c
}

func TestDiscoveryAndJWKS(t *testing.T) {
	f := newFixture(t)
	resp, _ := http.Get(f.http.URL + "/.well-known/openid-configuration")
	var d map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&d)
	if d["issuer"] != "https://idp.example" || d["jwks_uri"] != "https://idp.example/jwks.json" {
		t.Fatalf("bad discovery: %v", d)
	}
	resp, _ = http.Get(f.http.URL + "/jwks.json")
	var set keys.JWKS
	_ = json.NewDecoder(resp.Body).Decode(&set)
	if len(set.Keys) == 0 || set.Keys[0].N == "" || resp.Header.Get("Cache-Control") == "" {
		t.Fatalf("bad jwks: %+v", set)
	}
}

func TestCodeFlowWithPKCE(t *testing.T) {
	f := newFixture(t)
	status, body := f.exchange(f.login("bob", "battery staple"))
	if status != 200 {
		t.Fatalf("exchange: %d %v", status, body)
	}
	access := f.parse(body["access_token"].(string), "api")
	if access.String("sub") != "bob" || strings.Join(access.Strings("roles"), ",") != "user,admin" || access.String("jti") == "" {
		t.Fatalf("access claims: %v", access)
	}
	id := f.parse(body["id_token"].(string), "web")
	if id.String("nonce") != "n0" || id.String("email") != "bob@example.com" {
		t.Fatalf("id_token claims: %v", id)
	}
	if body["refresh_token"] == "" {
		t.Fatal("no refresh token")
	}
}

func TestAuthorizeRejections(t *testing.T) {
	f := newFixture(t)

	// Unregistered redirect_uri: shown on our page, never redirected to.
	resp := f.authorize("alice", "correct horse", func(v url.Values) { v.Set("redirect_uri", "https://evil.example/cb") })
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("bad redirect_uri: status %d location %q", resp.StatusCode, resp.Header.Get("Location"))
	}

	// GET without PKCE, or with "plain", comes back to the client as an error.
	for name, q := range map[string]url.Values{
		"no pkce":   {"response_type": {"code"}, "client_id": {"web"}, "redirect_uri": {redirect}, "scope": {"openid"}, "state": {"s"}},
		"plain":     {"response_type": {"code"}, "client_id": {"web"}, "redirect_uri": {redirect}, "scope": {"openid"}, "state": {"s"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"plain"}},
		"no openid": {"response_type": {"code"}, "client_id": {"web"}, "redirect_uri": {redirect}, "scope": {"profile"}, "code_challenge": {strings.Repeat("a", 43)}, "code_challenge_method": {"S256"}},
	} {
		resp, _ := noFollow.Get(f.http.URL + "/authorize?" + q.Encode())
		loc, _ := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != 302 || loc.Query().Get("error") == "" {
			t.Fatalf("%s: status %d location %s", name, resp.StatusCode, loc)
		}
	}
}

func TestLoginFailuresAndLockout(t *testing.T) {
	f := newFixture(t)
	if r := f.authorize("alice", "wrong", nil); r.StatusCode != 401 {
		t.Fatalf("wrong password: %d", r.StatusCode)
	}
	if r := f.authorize("nobody", "wrong", nil); r.StatusCode != 401 {
		t.Fatalf("unknown user: %d", r.StatusCode)
	}
	for i := 0; i < 4; i++ {
		f.authorize("alice", "wrong", nil)
	}
	if r := f.authorize("alice", "correct horse", nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("after 5 failures even the right password should be locked out, got %d", r.StatusCode)
	}
	if r := f.authorize("bob", "battery staple", nil); r.StatusCode != 302 {
		t.Fatalf("lockout must be per user, bob got %d", r.StatusCode)
	}
}

func TestCodeMisuse(t *testing.T) {
	f := newFixture(t)

	code := f.login("alice", "correct horse")
	wrong := strings.Repeat("w", 50)
	status, body := f.post("/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirect}, "client_id": {"web"}, "code_verifier": {wrong}})
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("wrong PKCE verifier: %d %v", status, body)
	}

	code = f.login("alice", "correct horse")
	f.advance(2 * time.Minute)
	if status, _ := f.exchange(code); status != 400 {
		t.Fatalf("expired code accepted: %d", status)
	}
}

func TestCodeReplayRevokesIssuedTokens(t *testing.T) {
	f := newFixture(t)
	code := f.login("alice", "correct horse")
	_, first := f.exchange(code)
	jti := f.parse(first["access_token"].(string), "api").String("jti")

	status, body := f.exchange(code)
	if status != 400 || body["error"] != "invalid_grant" {
		t.Fatalf("replayed code: %d %v", status, body)
	}
	if !f.revoked.Has(jti) {
		t.Fatal("access token from the first exchange should be revoked")
	}
	if status, _ := f.refresh(first["refresh_token"].(string)); status != 400 {
		t.Fatalf("refresh token from the first exchange should be dead, got %d", status)
	}
}

func TestRefreshRotationAndReuseDetection(t *testing.T) {
	f := newFixture(t)
	_, b1 := f.exchange(f.login("alice", "correct horse"))
	rt1 := b1["refresh_token"].(string)

	status, b2 := f.refresh(rt1)
	if status != 200 || b2["refresh_token"] == rt1 || b2["id_token"] != nil {
		t.Fatalf("refresh: %d %v", status, b2)
	}
	rt2 := b2["refresh_token"].(string)
	jti2 := f.parse(b2["access_token"].(string), "api").String("jti")

	// The attacker replays rt1 ...
	status, body := f.refresh(rt1)
	if status != 400 || !strings.Contains(body["error_description"].(string), "reuse") {
		t.Fatalf("reuse not detected: %d %v", status, body)
	}
	// ... which also kills the legitimate user's current tokens.
	if status, _ := f.refresh(rt2); status != 400 {
		t.Fatal("current refresh token should be revoked with the family")
	}
	if !f.revoked.Has(jti2) {
		t.Fatal("current access token should be on the revocation list")
	}
}

func TestRevokeEndpoint(t *testing.T) {
	f := newFixture(t)
	_, b := f.exchange(f.login("alice", "correct horse"))
	access := b["access_token"].(string)

	if status, _ := f.post("/revoke", url.Values{"client_id": {"web"}, "token": {"not-a-token"}}); status != 200 {
		t.Fatalf("unknown token must still get 200 (RFC 7009), got %d", status)
	}
	if status, _ := f.post("/revoke", url.Values{"client_id": {"web"}, "token": {access}}); status != 200 {
		t.Fatal("revoke failed")
	}
	if !f.revoked.Has(f.parse(access, "api").String("jti")) {
		t.Fatal("access token not on revocation list")
	}

	req, _ := http.NewRequest("GET", f.http.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 401 {
		t.Fatalf("userinfo with revoked token: %d", resp.StatusCode)
	}

	f.post("/revoke", url.Values{"client_id": {"web"}, "token": {b["refresh_token"].(string)}})
	if status, _ := f.refresh(b["refresh_token"].(string)); status != 400 {
		t.Fatal("revoked refresh token still works")
	}
}

func TestUserinfoAndInternalFeed(t *testing.T) {
	f := newFixture(t)
	_, b := f.exchange(f.login("bob", "battery staple"))
	req, _ := http.NewRequest("GET", f.http.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+b["access_token"].(string))
	resp, _ := http.DefaultClient.Do(req)
	var info map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&info)
	if resp.StatusCode != 200 || info["email"] != "bob@example.com" {
		t.Fatalf("userinfo: %d %v", resp.StatusCode, info)
	}

	resp, _ = http.Get(f.http.URL + "/internal/revocations")
	if resp.StatusCode != 403 {
		t.Fatalf("revocation feed without secret: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("GET", f.http.URL+"/internal/revocations", nil)
	req.Header.Set("Authorization", "Bearer s3cret")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 200 {
		t.Fatalf("revocation feed with secret: %d", resp.StatusCode)
	}
}

func TestConfidentialClientAuth(t *testing.T) {
	f := newFixture(t)
	req, _ := http.NewRequest("POST", f.http.URL+"/token", strings.NewReader("grant_type=refresh_token&refresh_token=x"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth("svc", "wrong")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 401 {
		t.Fatalf("bad client secret: %d", resp.StatusCode)
	}
	if status, _ := f.post("/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"}, "client_id": {"svc"}}); status != 401 {
		t.Fatalf("confidential client without secret: %d", status)
	}
}
