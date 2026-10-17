package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/json"
	"flag"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/idp"
	"github.com/AdityaTiwarime/gatekeep/internal/proxy"
)

//go:embed web
var webFiles embed.FS

// runDemo starts the IdP, the proxy, a tiny backend and the web page on one
// port, which is what a single free hosting slot gives you:
//
//	/idp/*  identity provider
//	/api/*  authenticating proxy -> backend
//	/       demo web app (a public OIDC client using PKCE)
func runDemo(ctx context.Context, log *slog.Logger, args []string) error {
	flags := flag.NewFlagSet("demo", flag.ExitOnError)
	addr := flags.String("addr", ":"+env("PORT", "8080"), "listen address")
	public := flags.String("public-url", env("RENDER_EXTERNAL_URL", ""), "public base URL (default http://localhost:<port>)")
	_ = flags.Parse(args)

	_, port, err := net.SplitHostPort(*addr)
	if err != nil {
		return err
	}
	base := strings.TrimRight(*public, "/")
	if base == "" {
		base = "http://localhost:" + port
	}
	loop := "http://127.0.0.1:" + port // how the proxy reaches the IdP inside the same process

	secret := randomSecret()
	parts, err := buildIDP(base+"/idp", "gatekeep-api", secret,
		[]*idp.Client{{ID: "demo-web", RedirectURIs: []string{base + "/"}}}, 5*time.Minute)
	if err != nil {
		return err
	}
	background(ctx, log, parts, 15*time.Minute)

	backend, err := startBackend(ctx)
	if err != nil {
		return err
	}
	client := &http.Client{Timeout: 5 * time.Second}
	cache := proxy.NewJWKSCache(loop+"/idp/jwks.json", client, 10*time.Second)
	px := proxy.New(proxy.Config{
		Upstream: backend, Issuer: base + "/idp", Audience: "gatekeep-api", Leeway: 30 * time.Second,
		Rules: []proxy.Rule{
			{Prefix: "/api/health", Public: true},
			{Prefix: "/api/admin", Role: "admin"},
			{Prefix: "/api/"},
		},
		RevocationsURL: loop + "/idp/internal/revocations", InternalSecret: secret,
		HTTPClient: client, Logger: log,
	}, cache)
	go func() {
		time.Sleep(300 * time.Millisecond) // let the listener come up first
		px.PollRevocations(ctx, 3*time.Second)
	}()

	static, _ := fs.Sub(webFiles, "web")
	mux := http.NewServeMux()
	mux.Handle("/idp/", http.StripPrefix("/idp", parts.srv.Handler()))
	mux.Handle("/api/", px)
	mux.Handle("POST /demo/rotate", rotateHandler(parts))
	mux.Handle("/", noCache(http.FileServerFS(static)))
	return serve(ctx, log, *addr, mux, "", "")
}

// startBackend runs the "protected app". It knows nothing about tokens:
// it simply trusts the identity headers the proxy sets.
func startBackend(ctx context.Context) (*url.URL, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(v)
	}
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/api/hello", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{
			"message": "Hello, " + r.Header.Get("X-Auth-User") + "! This came from the backend.",
			"backend_saw": map[string]string{
				"X-Auth-User":   r.Header.Get("X-Auth-User"),
				"X-Auth-Roles":  r.Header.Get("X-Auth-Roles"),
				"X-Auth-Client": r.Header.Get("X-Auth-Client"),
				"Authorization": r.Header.Get("Authorization"),
			},
		})
	})
	mux.HandleFunc("/api/admin", func(w http.ResponseWriter, r *http.Request) {
		reply(w, map[string]any{"message": "Admin area. Only tokens with the admin role get here.", "user": r.Header.Get("X-Auth-User")})
	})
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	go func() { <-ctx.Done(); _ = srv.Close() }()
	return url.Parse("http://" + ln.Addr().String())
}

// rotateHandler lets the demo page trigger a key rotation, at most once
// every 10 seconds so nobody can burn CPU generating RSA keys.
func rotateHandler(p *idpParts) http.Handler {
	var mu sync.Mutex
	var last time.Time
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if time.Since(last) < 10*time.Second {
			mu.Unlock()
			http.Error(w, `{"error":"slow_down","error_description":"one rotation per 10 seconds"}`, http.StatusTooManyRequests)
			return
		}
		last = time.Now()
		mu.Unlock()
		kid, err := p.keys.Rotate()
		if err != nil {
			http.Error(w, "rotation failed", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"active_kid": kid, "published_keys": len(p.keys.Set().Keys)})
	})
}

func noCache(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.ServeHTTP(w, r)
	})
}

func randomSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
