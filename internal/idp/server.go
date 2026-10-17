// Package idp is a small OpenID Connect provider: authorization code flow
// with mandatory PKCE, rotating refresh tokens with reuse detection,
// token revocation (RFC 7009) and a JWKS endpoint backed by rotating keys.
package idp

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/jwt"
	"github.com/AdityaTiwarime/gatekeep/internal/keys"
	"github.com/AdityaTiwarime/gatekeep/internal/revoke"
)

type Client struct {
	ID           string
	Secret       string // empty for public clients (browser apps), which must use PKCE
	RedirectURIs []string
}

type Config struct {
	Issuer         string // public base URL, e.g. https://auth.example.com/idp
	APIAudience    string // aud of access tokens
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	CodeTTL        time.Duration
	InternalSecret string // shared with the proxy for the revocation feed
	Keys           *keys.Manager
	Revoked        *revoke.List
	Now            func() time.Time
}

type authCode struct {
	clientID, redirectURI, challenge, nonce, scope string
	user                                           *User
	expires                                        time.Time
	used                                           bool
	family                                         string // set once redeemed
}

// family groups every token that descends from one login, so a stolen
// refresh token can take the whole chain down with it.
type family struct {
	id       string
	user     *User
	clientID string
	scope    string
	revoked  bool
	access   []revoke.Entry
}

type refreshToken struct {
	family  string
	expires time.Time
	used    bool
}

type Server struct {
	cfg     Config
	clients map[string]*Client
	users   map[string]*User
	locks   lockout

	mu       sync.Mutex
	codes    map[string]*authCode
	refresh  map[string]*refreshToken // key = sha256(token), raw tokens are never stored
	families map[string]*family
}

func New(cfg Config, clients []*Client, users []*User) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Server{
		cfg: cfg, clients: map[string]*Client{}, users: map[string]*User{},
		locks: lockout{fail: map[string][]time.Time{}},
		codes: map[string]*authCode{}, refresh: map[string]*refreshToken{}, families: map[string]*family{},
	}
	for _, c := range clients {
		s.clients[c.ID] = c
	}
	for _, u := range users {
		s.users[u.Username] = u
	}
	return s
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("GET /jwks.json", s.jwks)
	mux.HandleFunc("GET /authorize", s.authorizeForm)
	mux.HandleFunc("POST /authorize", s.authorizeSubmit)
	mux.HandleFunc("POST /token", s.token)
	mux.HandleFunc("POST /revoke", s.revoke)
	mux.HandleFunc("GET /userinfo", s.userinfo)
	mux.HandleFunc("GET /internal/revocations", s.revocations)
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY") // the login page must never be framed (clickjacking)
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

// ---------- discovery & keys ----------

func (s *Server) discovery(w http.ResponseWriter, r *http.Request) {
	iss := s.cfg.Issuer
	writeJSON(w, 200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/authorize",
		"token_endpoint":                        iss + "/token",
		"userinfo_endpoint":                     iss + "/userinfo",
		"revocation_endpoint":                   iss + "/revoke",
		"jwks_uri":                              iss + "/jwks.json",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_basic"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, 200, s.cfg.Keys.Set())
}

// ---------- /authorize ----------

type authRequest struct {
	ClientID, RedirectURI, State, Scope, Nonce, Challenge string
}

var errNoRedirect = errors.New("invalid client or redirect_uri")

// parseAuthRequest checks the request. Client and redirect_uri errors are
// shown on our own page: we must never redirect to an unregistered URI.
func (s *Server) parseAuthRequest(v url.Values) (authRequest, string, error) {
	ar := authRequest{
		ClientID: v.Get("client_id"), RedirectURI: v.Get("redirect_uri"), State: v.Get("state"),
		Scope: v.Get("scope"), Nonce: v.Get("nonce"), Challenge: v.Get("code_challenge"),
	}
	c := s.clients[ar.ClientID]
	if c == nil || !slices.Contains(c.RedirectURIs, ar.RedirectURI) {
		return ar, "", errNoRedirect
	}
	switch {
	case v.Get("response_type") != "code":
		return ar, "unsupported_response_type", nil
	case !slices.Contains(strings.Fields(ar.Scope), "openid"):
		return ar, "invalid_scope", nil
	case v.Get("code_challenge_method") != "S256" || len(ar.Challenge) < 43 || len(ar.Challenge) > 128:
		// PKCE is required for every client and "plain" is refused.
		return ar, "invalid_request", nil
	}
	return ar, "", nil
}

func redirectError(w http.ResponseWriter, r *http.Request, ar authRequest, code string) {
	u, _ := url.Parse(ar.RedirectURI)
	q := u.Query()
	q.Set("error", code)
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) authorizeForm(w http.ResponseWriter, r *http.Request) {
	ar, oauthErr, err := s.parseAuthRequest(r.URL.Query())
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if oauthErr != "" {
		redirectError(w, r, ar, oauthErr)
		return
	}
	renderLogin(w, 200, ar, "")
}

func (s *Server) authorizeSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	v := r.PostForm
	v.Set("response_type", "code")
	v.Set("code_challenge_method", "S256")
	ar, oauthErr, err := s.parseAuthRequest(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if oauthErr != "" {
		redirectError(w, r, ar, oauthErr)
		return
	}

	now := s.cfg.Now()
	name := strings.TrimSpace(v.Get("username"))
	if s.locks.locked(name, now) {
		renderLogin(w, http.StatusTooManyRequests, ar, "Too many failed attempts. Try again in a few minutes.")
		return
	}
	u, ok := s.users[name]
	if !ok {
		dummy.check(v.Get("password")) // same cost as a real check
		s.locks.failed(name, now)
		renderLogin(w, http.StatusUnauthorized, ar, "Wrong username or password.")
		return
	}
	if !u.check(v.Get("password")) {
		s.locks.failed(name, now)
		renderLogin(w, http.StatusUnauthorized, ar, "Wrong username or password.")
		return
	}
	s.locks.reset(name)

	code := randomToken()
	s.mu.Lock()
	s.codes[code] = &authCode{
		clientID: ar.ClientID, redirectURI: ar.RedirectURI, challenge: ar.Challenge,
		nonce: ar.Nonce, scope: ar.Scope, user: u, expires: now.Add(s.cfg.CodeTTL),
	}
	s.mu.Unlock()

	dest, _ := url.Parse(ar.RedirectURI)
	q := dest.Query()
	q.Set("code", code)
	if ar.State != "" {
		q.Set("state", ar.State)
	}
	q.Set("iss", s.cfg.Issuer) // RFC 9207: lets the client detect mix-up attacks
	dest.RawQuery = q.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

// ---------- /token ----------

type oauthError struct {
	status int
	code   string
	desc   string
}

func (e *oauthError) Error() string { return e.code + ": " + e.desc }

func invalidGrant(desc string) *oauthError { return &oauthError{400, "invalid_grant", desc} }

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, &oauthError{400, "invalid_request", "bad form body"})
		return
	}
	client, oe := s.authenticateClient(r)
	if oe != nil {
		writeOAuthError(w, oe)
		return
	}

	var resp map[string]any
	var err *oauthError
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		resp, err = s.exchangeCode(client, r.PostForm)
	case "refresh_token":
		resp, err = s.exchangeRefresh(client, r.PostForm.Get("refresh_token"))
	default:
		err = &oauthError{400, "unsupported_grant_type", ""}
	}
	if err != nil {
		writeOAuthError(w, err)
		return
	}
	writeJSON(w, 200, resp)
}

func (s *Server) authenticateClient(r *http.Request) (*Client, *oauthError) {
	id, secret, basic := r.BasicAuth()
	if !basic {
		id = r.PostForm.Get("client_id")
	}
	c := s.clients[id]
	bad := &oauthError{401, "invalid_client", "unknown client or bad credentials"}
	if c == nil {
		return nil, bad
	}
	if c.Secret != "" && (!basic || subtle.ConstantTimeCompare([]byte(secret), []byte(c.Secret)) != 1) {
		return nil, bad
	}
	return c, nil
}

func (s *Server) exchangeCode(c *Client, v url.Values) (map[string]any, *oauthError) {
	now := s.cfg.Now()
	s.mu.Lock()
	ac := s.codes[v.Get("code")]
	if ac == nil {
		s.mu.Unlock()
		return nil, invalidGrant("unknown code")
	}
	if ac.used {
		// A code showing up twice means it leaked. Kill what it produced (RFC 6749 §4.1.2).
		fam := ac.family
		s.mu.Unlock()
		s.revokeFamily(fam)
		return nil, invalidGrant("code already used; tokens issued from it were revoked")
	}
	if now.After(ac.expires) || ac.clientID != c.ID || ac.redirectURI != v.Get("redirect_uri") {
		s.mu.Unlock()
		return nil, invalidGrant("code expired or not issued to this client/redirect_uri")
	}
	if !verifyPKCE(v.Get("code_verifier"), ac.challenge) {
		s.mu.Unlock()
		return nil, invalidGrant("PKCE verification failed")
	}
	ac.used = true
	fam := &family{id: randomToken(), user: ac.user, clientID: c.ID, scope: ac.scope}
	s.families[fam.id] = fam
	ac.family = fam.id
	s.mu.Unlock()

	return s.issue(fam, ac.nonce, true)
}

func (s *Server) exchangeRefresh(c *Client, raw string) (map[string]any, *oauthError) {
	if raw == "" {
		return nil, &oauthError{400, "invalid_request", "missing refresh_token"}
	}
	s.mu.Lock()
	rt := s.refresh[hashToken(raw)]
	if rt == nil {
		s.mu.Unlock()
		return nil, invalidGrant("unknown refresh token")
	}
	fam := s.families[rt.family]
	if rt.used {
		// Rotation means each refresh token works once. Seeing one again means
		// two parties hold it, so the whole family is revoked.
		s.mu.Unlock()
		s.revokeFamily(rt.family)
		return nil, invalidGrant("refresh token reuse detected; session revoked")
	}
	if fam == nil || fam.revoked || fam.clientID != c.ID || s.cfg.Now().After(rt.expires) {
		s.mu.Unlock()
		return nil, invalidGrant("refresh token expired, revoked or not issued to this client")
	}
	rt.used = true
	s.mu.Unlock()
	return s.issue(fam, "", false)
}

func (s *Server) issue(fam *family, nonce string, withIDToken bool) (map[string]any, *oauthError) {
	now := s.cfg.Now()
	u := fam.user
	jti := randomToken()
	exp := now.Add(s.cfg.AccessTTL)
	access, err := s.cfg.Keys.Sign(jwt.Claims{
		"iss": s.cfg.Issuer, "sub": u.Username, "aud": s.cfg.APIAudience,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": exp.Unix(), "jti": jti,
		"client_id": fam.clientID, "scope": fam.scope, "sid": fam.id,
		"roles": u.Roles, "name": u.Name,
	})
	if err != nil {
		return nil, &oauthError{500, "server_error", "signing failed"}
	}
	resp := map[string]any{
		"access_token": access, "token_type": "Bearer",
		"expires_in": int(s.cfg.AccessTTL.Seconds()), "scope": fam.scope,
	}
	if withIDToken {
		idc := jwt.Claims{
			"iss": s.cfg.Issuer, "sub": u.Username, "aud": fam.clientID,
			"iat": now.Unix(), "exp": exp.Unix(), "auth_time": now.Unix(),
			"name": u.Name, "email": u.Email,
		}
		if nonce != "" {
			idc["nonce"] = nonce
		}
		idt, err := s.cfg.Keys.Sign(idc)
		if err != nil {
			return nil, &oauthError{500, "server_error", "signing failed"}
		}
		resp["id_token"] = idt
	}

	raw := randomToken()
	s.mu.Lock()
	fam.access = append(fam.access, revoke.Entry{JTI: jti, Exp: exp.Unix()})
	s.refresh[hashToken(raw)] = &refreshToken{family: fam.id, expires: now.Add(s.cfg.RefreshTTL)}
	s.mu.Unlock()
	resp["refresh_token"] = raw
	return resp, nil
}

func (s *Server) revokeFamily(id string) {
	s.mu.Lock()
	fam := s.families[id]
	if fam == nil {
		s.mu.Unlock()
		return
	}
	fam.revoked = true
	access := slices.Clone(fam.access)
	s.mu.Unlock()
	for _, e := range access {
		s.cfg.Revoked.Add(e.JTI, time.Unix(e.Exp, 0))
	}
}

// ---------- /revoke (RFC 7009) ----------

func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, &oauthError{400, "invalid_request", "bad form body"})
		return
	}
	client, oe := s.authenticateClient(r)
	if oe != nil {
		writeOAuthError(w, oe)
		return
	}
	tok := r.PostForm.Get("token")

	s.mu.Lock()
	rt := s.refresh[hashToken(tok)]
	var famID string
	if rt != nil && s.families[rt.family] != nil && s.families[rt.family].clientID == client.ID {
		famID = rt.family
	}
	s.mu.Unlock()
	if famID != "" {
		s.revokeFamily(famID)
	} else if _, c, err := jwt.Parse(tok, s.cfg.Keys.PublicKey, jwt.Options{Issuer: s.cfg.Issuer, Now: s.cfg.Now}); err == nil && c.String("client_id") == client.ID {
		exp, _ := c.Time("exp")
		s.cfg.Revoked.Add(c.String("jti"), exp)
	}
	// RFC 7009: answer 200 whether or not the token was valid, so the
	// endpoint can't be used to probe which tokens exist.
	w.WriteHeader(http.StatusOK)
}

// ---------- /userinfo ----------

func (s *Server) userinfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gatekeep"`)
		writeOAuthError(w, &oauthError{401, "invalid_token", "missing bearer token"})
		return
	}
	_, c, err := jwt.Parse(tok, s.cfg.Keys.PublicKey, jwt.Options{
		Issuer: s.cfg.Issuer, Audience: s.cfg.APIAudience, Leeway: 30 * time.Second, Now: s.cfg.Now,
	})
	if err != nil || s.cfg.Revoked.Has(c.String("jti")) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, &oauthError{401, "invalid_token", "token invalid, expired or revoked"})
		return
	}
	u := s.users[c.String("sub")]
	if u == nil {
		writeOAuthError(w, &oauthError{401, "invalid_token", "unknown subject"})
		return
	}
	writeJSON(w, 200, map[string]any{"sub": u.Username, "name": u.Name, "email": u.Email, "roles": u.Roles})
}

// ---------- revocation feed for the proxy ----------

func (s *Server) revocations(w http.ResponseWriter, r *http.Request) {
	got, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if s.cfg.InternalSecret == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.cfg.InternalSecret)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"revoked": s.cfg.Revoked.Snapshot()})
}

// Sweep drops expired codes, refresh tokens and families. Call it periodically.
func (s *Server) Sweep() {
	now := s.cfg.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, c := range s.codes {
		if now.After(c.expires.Add(10 * time.Minute)) { // kept a little longer so reuse is still detected
			delete(s.codes, k)
		}
	}
	live := map[string]bool{}
	for k, t := range s.refresh {
		if now.After(t.expires) {
			delete(s.refresh, k)
			continue
		}
		live[t.family] = true
	}
	for id := range s.families {
		if !live[id] {
			delete(s.families, id)
		}
	}
	s.cfg.Revoked.Snapshot()
}

// ---------- helpers ----------

func verifyPKCE(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(got), []byte(challenge)) == 1
}

func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // the system RNG failing is not something to carry on from
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, e *oauthError) {
	body := map[string]string{"error": e.code}
	if e.desc != "" {
		body["error_description"] = e.desc
	}
	writeJSON(w, e.status, body)
}

var loginPage = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in · GateKeep</title>
<style>
body{font-family:system-ui,sans-serif;background:#f4f5f7;color:#1d2330;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px}
form{background:#fff;padding:28px;border-radius:12px;box-shadow:0 2px 12px #0001;width:min(340px,100%)}
h1{font-size:20px;margin:0 0 4px}p{color:#5b6475;font-size:14px;margin:0 0 18px}
label{display:block;font-size:13px;margin:12px 0 4px}input{width:100%;padding:10px;border:1px solid #c9ced8;border-radius:8px;font-size:15px;box-sizing:border-box}
button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:8px;background:#2f5bd3;color:#fff;font-size:15px;cursor:pointer}
.err{background:#fdecec;color:#a11b1b;padding:9px 11px;border-radius:8px;font-size:14px;margin-bottom:6px}
</style></head><body>
<form method="post" action="authorize">
<h1>Sign in</h1><p>to continue to <b>{{.Req.ClientID}}</b></p>
{{if .Error}}<div class="err" role="alert">{{.Error}}</div>{{end}}
<label for="u">Username</label><input id="u" name="username" autocomplete="username" required autofocus>
<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password" required>
<input type="hidden" name="client_id" value="{{.Req.ClientID}}">
<input type="hidden" name="redirect_uri" value="{{.Req.RedirectURI}}">
<input type="hidden" name="state" value="{{.Req.State}}">
<input type="hidden" name="scope" value="{{.Req.Scope}}">
<input type="hidden" name="nonce" value="{{.Req.Nonce}}">
<input type="hidden" name="code_challenge" value="{{.Req.Challenge}}">
<button>Sign in</button>
</form></body></html>`))

func renderLogin(w http.ResponseWriter, status int, ar authRequest, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'")
	w.WriteHeader(status)
	_ = loginPage.Execute(w, map[string]any{"Req": ar, "Error": msg})
}
