// Command gatekeep runs the identity provider, the authenticating proxy,
// a certificate helper, or everything together as a demo.
//
//	gatekeep certs  -out ./certs -hosts localhost,127.0.0.1
//	gatekeep idp    -addr :9000 -issuer http://localhost:9000
//	gatekeep proxy  -addr :8443 -upstream http://localhost:8080 -issuer http://localhost:9000 -tls-cert ... -tls-key ...
//	gatekeep demo   -addr :8080
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/AdityaTiwarime/gatekeep/internal/idp"
	"github.com/AdityaTiwarime/gatekeep/internal/keys"
	"github.com/AdityaTiwarime/gatekeep/internal/pki"
	"github.com/AdityaTiwarime/gatekeep/internal/proxy"
	"github.com/AdityaTiwarime/gatekeep/internal/revoke"
)

var version = "dev" // set at build time with -ldflags "-X main.version=..."

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	switch os.Args[1] {
	case "certs":
		err = runCerts(os.Args[2:])
	case "idp":
		err = runIDP(ctx, log, os.Args[2:])
	case "proxy":
		err = runProxy(ctx, log, os.Args[2:])
	case "demo":
		err = runDemo(ctx, log, os.Args[2:])
	case "version", "-v", "--version":
		fmt.Println("gatekeep", version)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: gatekeep <certs|idp|proxy|demo|version> [flags]")
}

func env(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// ---------- certs ----------

func runCerts(args []string) error {
	fs := flag.NewFlagSet("certs", flag.ExitOnError)
	out := fs.String("out", "certs", "output directory")
	hosts := fs.String("hosts", "localhost,127.0.0.1", "comma-separated DNS names / IPs for the server cert")
	days := fs.Int("days", 90, "server certificate lifetime in days")
	_ = fs.Parse(args)

	ca, err := pki.NewCA("GateKeep Local CA", 365*24*time.Hour)
	if err != nil {
		return err
	}
	certPEM, keyPEM, err := ca.IssueServer(splitList(*hosts), time.Duration(*days)*24*time.Hour)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return err
	}
	files := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"ca.pem", ca.PEM, 0o644}, {"server.pem", certPEM, 0o644}, {"server-key.pem", keyPEM, 0o600},
	}
	for _, f := range files {
		if err := os.WriteFile(filepath.Join(*out, f.name), f.data, f.mode); err != nil {
			return err
		}
	}
	fmt.Printf("wrote %s/{ca.pem,server.pem,server-key.pem} for %s\n", *out, *hosts)
	return nil
}

// ---------- shared setup ----------

func demoUsers() ([]*idp.User, error) {
	alice, err := idp.NewUser("alice", env("GATEKEEP_ALICE_PASSWORD", "alice-demo-pass"), "Alice Rao", "alice@example.com", "user")
	if err != nil {
		return nil, err
	}
	bob, err := idp.NewUser("bob", env("GATEKEEP_BOB_PASSWORD", "bob-demo-pass"), "Bob Menon", "bob@example.com", "user", "admin")
	if err != nil {
		return nil, err
	}
	return []*idp.User{alice, bob}, nil
}

type idpParts struct {
	srv     *idp.Server
	keys    *keys.Manager
	revoked *revoke.List
}

func buildIDP(issuer, audience, secret string, clients []*idp.Client, accessTTL time.Duration) (*idpParts, error) {
	km, err := keys.New(2048, 3*accessTTL) // a retired key stays published well past its last token
	if err != nil {
		return nil, err
	}
	users, err := demoUsers()
	if err != nil {
		return nil, err
	}
	rl := revoke.New()
	srv := idp.New(idp.Config{
		Issuer: issuer, APIAudience: audience, InternalSecret: secret,
		AccessTTL: accessTTL, RefreshTTL: 8 * time.Hour, CodeTTL: time.Minute,
		Keys: km, Revoked: rl,
	}, clients, users)
	return &idpParts{srv: srv, keys: km, revoked: rl}, nil
}

func background(ctx context.Context, log *slog.Logger, p *idpParts, rotateEvery time.Duration) {
	go p.keys.RunRotation(ctx, rotateEvery, func(err error) { log.Error("key rotation failed", "err", err) })
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				p.srv.Sweep()
			}
		}
	}()
}

func serve(ctx context.Context, log *slog.Logger, addr string, h http.Handler, certFile, keyFile string) error {
	srv := &http.Server{
		Addr: addr, Handler: h,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	if certFile != "" {
		certPEM, err := os.ReadFile(certFile)
		if err != nil {
			return err
		}
		keyPEM, err := os.ReadFile(keyFile)
		if err != nil {
			return err
		}
		if srv.TLSConfig, err = pki.ServerTLS(certPEM, keyPEM); err != nil {
			return err
		}
	}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr, "tls", certFile != "")
		if certFile != "" {
			errc <- srv.ListenAndServeTLS("", "")
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		log.Info("shutting down")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(sctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	}
}

// ---------- idp ----------

func runIDP(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("idp", flag.ExitOnError)
	addr := fs.String("addr", ":9000", "listen address")
	issuer := fs.String("issuer", "http://localhost:9000", "public issuer URL")
	audience := fs.String("audience", "gatekeep-api", "audience of access tokens")
	client := fs.String("client", "demo-web=http://localhost:8443/", "public client as id=redirect_uri[,redirect_uri]")
	tlsCert := fs.String("tls-cert", "", "TLS certificate (PEM)")
	tlsKey := fs.String("tls-key", "", "TLS private key (PEM)")
	rotate := fs.Duration("rotate-every", 24*time.Hour, "signing key rotation interval")
	_ = fs.Parse(args)

	secret := os.Getenv("GATEKEEP_INTERNAL_SECRET")
	if secret == "" {
		return errors.New("GATEKEEP_INTERNAL_SECRET must be set (shared with the proxy)")
	}
	id, uris, ok := strings.Cut(*client, "=")
	if !ok {
		return errors.New("-client must look like id=redirect_uri")
	}
	p, err := buildIDP(strings.TrimRight(*issuer, "/"), *audience, secret,
		[]*idp.Client{{ID: id, RedirectURIs: splitList(uris)}}, 10*time.Minute)
	if err != nil {
		return err
	}
	background(ctx, log, p, *rotate)
	return serve(ctx, log, *addr, p.srv.Handler(), *tlsCert, *tlsKey)
}

// ---------- proxy ----------

type ruleFlags []proxy.Rule

func (r *ruleFlags) String() string { return fmt.Sprint(*r) }
func (r *ruleFlags) Set(v string) error {
	prefix, need, ok := strings.Cut(v, "=")
	if !ok || !strings.HasPrefix(prefix, "/") {
		return errors.New("rule must look like /path=public|any|<role>")
	}
	rule := proxy.Rule{Prefix: prefix}
	switch need {
	case "public":
		rule.Public = true
	case "any":
	default:
		rule.Role = need
	}
	*r = append(*r, rule)
	return nil
}

func runProxy(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("proxy", flag.ExitOnError)
	addr := fs.String("addr", ":8443", "listen address")
	upstream := fs.String("upstream", "http://localhost:8080", "backend URL")
	issuer := fs.String("issuer", "http://localhost:9000", "expected token issuer (also used to find the JWKS)")
	audience := fs.String("audience", "gatekeep-api", "expected token audience")
	leeway := fs.Duration("leeway", 30*time.Second, "allowed clock skew")
	poll := fs.Duration("revocation-poll", 5*time.Second, "how often to pull the revocation list")
	tlsCert := fs.String("tls-cert", "", "TLS certificate (PEM) - terminate TLS here")
	tlsKey := fs.String("tls-key", "", "TLS private key (PEM)")
	var rules ruleFlags
	fs.Var(&rules, "rule", "access rule, repeatable: /path=public|any|<role>")
	_ = fs.Parse(args)

	up, err := url.Parse(*upstream)
	if err != nil || up.Host == "" {
		return fmt.Errorf("bad -upstream %q", *upstream)
	}
	iss := strings.TrimRight(*issuer, "/")
	client := &http.Client{Timeout: 5 * time.Second}
	cache := proxy.NewJWKSCache(iss+"/jwks.json", client, 10*time.Second)
	if err := cache.Refresh(); err != nil {
		log.Warn("initial JWKS fetch failed, will retry on first request", "err", err)
	}
	p := proxy.New(proxy.Config{
		Upstream: up, Issuer: iss, Audience: *audience, Leeway: *leeway, Rules: rules,
		RevocationsURL: iss + "/internal/revocations", InternalSecret: os.Getenv("GATEKEEP_INTERNAL_SECRET"),
		HTTPClient: client, Logger: log,
	}, cache)
	go p.PollRevocations(ctx, *poll)
	return serve(ctx, log, *addr, p, *tlsCert, *tlsKey)
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}
