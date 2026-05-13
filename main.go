// Package main is the litterbox HTTP server entrypoint.
//
// litterbox is a standalone single-binary web app that signs the user
// into RealDebrid via the OAuth device-code flow, reports the count
// of broken vs healthy torrents in their library, and offers a
// bulk-delete affordance for the broken ones.
//
// The server has two responsibilities:
//
//  1. Serve the static frontend (embedded HTML/CSS/JS via embed.FS).
//  2. Proxy browser-originated RD API calls through /api/proxy —
//     RD's API doesn't return CORS headers, so a browser-only SPA
//     can't talk to it directly. The proxy validates each request
//     against a hostname allowlist (api.real-debrid.com only) and
//     forwards the Authorization header the browser supplies. It
//     does NOT store tokens or any user state — the OAuth token
//     lives entirely in the user's localStorage.
//
// Stateless by design so the Deployment can run with replicas > 1
// behind a Service without a shared store. Each replica handles any
// request independently; the user's browser is the only place that
// knows which session is theirs.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"litterbox/internal/server"
)

// staticFS embeds the entire web/ directory at compile time. Declared
// here in main.go (project root) because Go's embed directive resolves
// relative to the file's package directory — keeping web/ at the
// root keeps the layout obvious. fs.Sub strips the `web/` prefix
// before handing the tree to the static file server.
//
//go:embed all:web
var staticFS embed.FS

// manifestJSON pulls the release-please manifest into the binary so
// /api/version can serve whatever version was current at build time
// without needing ldflag plumbing. release-please bumps this file
// before tagging, so a binary built from a release tag carries the
// matching version automatically.
//
//go:embed .release-please-manifest.json
var manifestJSON []byte

func readVersion() string {
	var m map[string]string
	if err := json.Unmarshal(manifestJSON, &m); err != nil {
		return "dev"
	}
	if v, ok := m["."]; ok && v != "" {
		return v
	}
	return "dev"
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	addr := os.Getenv("LISTEN")
	if addr == "" {
		addr = ":8080"
	}

	webRoot, err := fs.Sub(staticFS, "web")
	if err != nil {
		log.Error("embed sub failed", "err", err)
		os.Exit(1)
	}
	cfg := server.Config{
		Version: readVersion(),
		// REDDIT_MEGATHREAD_URL — operator-rotatable per release cycle.
		// Defaults to a placeholder so an unset env var doesn't break the
		// "open megathread" button; the dashboard treats the placeholder
		// as benign (will still open Reddit, just lands on a 404-ish
		// search page). Production deploys override via the env-configmap.
		RedditMegathreadURL: envOr("REDDIT_MEGATHREAD_URL",
			"https://www.reddit.com/r/StremioAddons/PLACEHOLDER-LITTERBOX-MEGATHREAD"),
	}
	srv, err := server.New(log, webRoot, cfg)
	if err != nil {
		log.Error("server init failed", "err", err)
		os.Exit(1)
	}
	log.Info("litterbox starting", "version", cfg.Version, "megathread", cfg.RedditMegathreadURL)

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
		// No write timeout: the proxy passes through to RD, which can
		// take up to 15s on slow days. Inactivity is bounded by the
		// upstream call's own context timeout (set per request in
		// internal/proxy).
	}

	// Graceful shutdown: catch SIGTERM (k8s pod stop) + SIGINT (dev).
	// Drain in-flight requests so a rolling update doesn't 502 anyone
	// mid-OAuth-poll.
	shutdownCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()

	go func() {
		log.Info("litterbox listening", "addr", addr)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen failed", "err", err)
			os.Exit(1)
		}
	}()

	<-shutdownCtx.Done()
	log.Info("shutdown signal received; draining")
	drainCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(drainCtx); err != nil {
		log.Warn("shutdown drain failed", "err", err)
	}
}
