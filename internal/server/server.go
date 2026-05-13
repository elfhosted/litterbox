// Package server wires the HTTP routes for litterbox.
//
// Two route groups:
//
//   - Static: GET / (and any other path that maps to an embedded
//     file) serves the SPA. embed.FS is the single source of truth
//     for assets — no runtime filesystem reads, no missing-file
//     surprises in container.
//
//   - API: /api/proxy forwards a single browser request to RD's API
//     with the Authorization header the browser supplied. Stateless
//     by design — the OAuth token lives entirely in the user's
//     localStorage and is re-attached to every proxy call.
//
// Health endpoint: /healthz returns 200 OK on any GET, no body. Used
// by k8s liveness/readiness probes.
package server

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"

	"litterbox/internal/proxy"
)

// Config carries the runtime values the frontend needs (rendered
// into the page via /api/config). Add fields here when introducing
// new operator-rotatable knobs — the rest of the wiring is generic.
// Operator changes are picked up via configmap edit → stakater
// reloader pod restart, not per-request (config is marshaled once).
type Config struct {
	Version                string `json:"version"`
	RedditMegathreadURL    string `json:"redditMegathreadUrl"`
	RDBlockedFilenameRegex string `json:"rdBlockedFilenameRegex"`
}

// Server holds the mux + the proxy handler. Constructed once at
// process start; safe for concurrent use because every dependency
// (proxy.Handler, the embedded FS) is read-only at request time.
type Server struct {
	mux *http.ServeMux
	log *slog.Logger
}

// New constructs the HTTP server. webRoot is the filesystem
// containing the static assets (typically an embed.FS rooted at
// web/ — declared in main.go so the embed directive resolves
// relative to the project root). cfg holds the runtime values the
// frontend needs to render — served as JSON from /api/config.
//
// The server is intentionally minimal: a CORS-bypass proxy for the
// RD API, a healthz probe, a config endpoint, and the embedded
// static SPA. No server-side state — all pattern data lives in the
// user's browser localStorage.
func New(log *slog.Logger, webRoot fs.FS, cfg Config, outboundProxies []string, outboundUA string) (*Server, error) {
	mux := http.NewServeMux()

	// /api/proxy — RD CORS workaround. See internal/proxy for the
	// hostname allowlist and security posture. outboundProxies, if
	// non-empty, dilutes our egress IP fingerprint across the pool
	// so RD's per-IP rate limiter doesn't 429 us at scale.
	// outboundUA, if non-empty, replaces the browser's UA on every
	// outbound — hedge against RD WAF extending to broader UA rules.
	proxyHandler := proxy.New(log, outboundProxies, outboundUA)
	mux.Handle("/api/proxy", proxyHandler)
	mux.Handle("/api/proxy/", proxyHandler)

	// /api/config — JSON; fetched by the SPA on load. Carries the
	// build-time version (for the header chip) plus operator-rotatable
	// values like the current Reddit megathread URL.
	cfgBytes, _ := json.Marshal(cfg)
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(cfgBytes)
	})

	// /healthz — k8s probe.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Static assets served from the supplied FS, with a short
	// Cache-Control so a release rolling out gets picked up by
	// downstream caches (Cloudflare, browsers) within 5 minutes
	// instead of inheriting the zone-default multi-hour TTL — which
	// once left a renamed /api/version fetch baked into a cached
	// app.js, breaking the version chip until the cache aged out.
	mux.Handle("/", cacheControl(http.FileServer(http.FS(webRoot)), "max-age=300, must-revalidate"))

	return &Server{mux: mux, log: log}, nil
}

func cacheControl(h http.Handler, value string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", value)
		h.ServeHTTP(w, r)
	})
}

// ServeHTTP dispatches the request. ServeMux already handles
// longest-prefix routing; this method just delegates.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
