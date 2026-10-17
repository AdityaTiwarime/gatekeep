// Package proxy is an authenticating reverse proxy. It sits in front of a
// backend, validates the caller's access token against the IdP's JWKS,
// enforces role rules per path, and passes a trusted identity downstream.
package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/jwt"
	"github.com/AdityaTiwarime/gatekeep/internal/revoke"
)

// Identity headers the backend trusts. Anything a client sends with these
// names is deleted first, otherwise a caller could simply claim to be admin.
var identityHeaders = []string{
	"X-Auth-User", "X-Auth-Roles", "X-Auth-Scope", "X-Auth-Client",
	"X-Forwarded-User", "X-Remote-User", "X-User",
}

// Rule says what a path prefix needs. Longest prefix wins.
type Rule struct {
	Prefix string
	Public bool   // no token needed
	Role   string // token must carry this role; empty = any valid token
}

type Config struct {
	Upstream       *url.URL
	Issuer         string
	Audience       string
	Leeway         time.Duration
	Rules          []Rule
	ForwardToken   bool // pass the raw Authorization header to the backend
	RevocationsURL string
	InternalSecret string
	HTTPClient     *http.Client
	Logger         *slog.Logger
	Now            func() time.Time
}

type Proxy struct {
	cfg     Config
	keys    *JWKSCache
	revoked *revoke.List
	rp      *httputil.ReverseProxy
	rules   []Rule
}

func New(cfg Config, keys *JWKSCache) *Proxy {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	rules := append([]Rule(nil), cfg.Rules...)
	sort.Slice(rules, func(i, j int) bool { return len(rules[i].Prefix) > len(rules[j].Prefix) })

	p := &Proxy{cfg: cfg, keys: keys, revoked: revoke.New(), rules: rules}
	p.rp = &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(cfg.Upstream)
			pr.SetXForwarded() // replaces any client-supplied X-Forwarded-* with what we actually saw
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			cfg.Logger.Error("upstream failed", "path", r.URL.Path, "err", err)
			writeErr(w, http.StatusBadGateway, "bad_gateway", "upstream unavailable")
		},
	}
	return p
}

func (p *Proxy) ruleFor(path string) Rule {
	for _, r := range p.rules {
		if strings.HasPrefix(path, r.Prefix) {
			return r
		}
	}
	return Rule{} // default: any valid token
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rec := &statusRecorder{ResponseWriter: w, status: 200}
	start := p.cfg.Now()
	user := p.handle(rec, r)
	p.cfg.Logger.Info("request", "method", r.Method, "path", r.URL.Path, "status", rec.status,
		"user", user, "ms", p.cfg.Now().Sub(start).Milliseconds())
}

func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) string {
	for _, h := range identityHeaders {
		r.Header.Del(h)
	}
	rule := p.ruleFor(r.URL.Path)
	if rule.Public {
		r.Header.Del("Authorization")
		p.rp.ServeHTTP(w, r)
		return "-"
	}

	scheme, tok, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gatekeep"`)
		writeErr(w, http.StatusUnauthorized, "invalid_request", "missing bearer token")
		return "-"
	}
	_, c, err := jwt.Parse(strings.TrimSpace(tok), p.keys.KeyFor, jwt.Options{
		Issuer: p.cfg.Issuer, Audience: p.cfg.Audience, Leeway: p.cfg.Leeway, Now: p.cfg.Now,
	})
	if err == nil && p.revoked.Has(c.String("jti")) {
		err = errRevoked
	}
	if err != nil {
		// Detail goes to the log; the client only learns the token was rejected.
		p.cfg.Logger.Warn("token rejected", "path", r.URL.Path, "reason", err.Error())
		w.Header().Set("WWW-Authenticate", `Bearer realm="gatekeep", error="invalid_token"`)
		writeErr(w, http.StatusUnauthorized, "invalid_token", publicReason(err))
		return "-"
	}

	user, roles := c.String("sub"), c.Strings("roles")
	if rule.Role != "" && !contains(roles, rule.Role) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="gatekeep", error="insufficient_scope"`)
		writeErr(w, http.StatusForbidden, "insufficient_scope", "requires role "+rule.Role)
		return user
	}

	r.Header.Set("X-Auth-User", user)
	r.Header.Set("X-Auth-Roles", strings.Join(roles, ","))
	r.Header.Set("X-Auth-Scope", c.String("scope"))
	r.Header.Set("X-Auth-Client", c.String("client_id"))
	if !p.cfg.ForwardToken {
		r.Header.Del("Authorization") // the backend gets the identity, not a reusable credential
	}
	p.rp.ServeHTTP(w, r)
	return user
}

var errRevoked = errors.New("token revoked")

func publicReason(err error) string {
	switch {
	case errors.Is(err, jwt.ErrExpired):
		return "token expired"
	case errors.Is(err, errRevoked):
		return "token revoked"
	case errors.Is(err, jwt.ErrNotYetValid), errors.Is(err, jwt.ErrIssuedFuture):
		return "token not valid yet"
	}
	return "token invalid"
}

// PollRevocations keeps the local denylist in sync with the IdP. Between
// polls a revoked token can still pass: that window (interval) is the price
// of not calling the IdP on every request, so keep it short.
func (p *Proxy) PollRevocations(ctx context.Context, every time.Duration) {
	p.SyncRevocations(ctx)
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			p.SyncRevocations(ctx)
		}
	}
}

func (p *Proxy) SyncRevocations(ctx context.Context) {
	if p.cfg.RevocationsURL == "" {
		return
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.RevocationsURL, nil)
	req.Header.Set("Authorization", "Bearer "+p.cfg.InternalSecret)
	resp, err := p.cfg.HTTPClient.Do(req)
	if err != nil {
		p.cfg.Logger.Warn("revocation sync failed", "err", err)
		return // keep the last known list rather than forgetting revocations
	}
	defer resp.Body.Close()
	var body struct {
		Revoked []revoke.Entry `json:"revoked"`
	}
	if resp.StatusCode != 200 || json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&body) != nil {
		p.cfg.Logger.Warn("revocation sync failed", "status", resp.StatusCode)
		return
	}
	p.revoked.Replace(body.Revoked)
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func writeErr(w http.ResponseWriter, status int, code, desc string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": desc})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
