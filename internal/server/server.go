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
	"io/fs"
	"log/slog"
	"net/http"

	"litterbox/internal/proxy"
)

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
// relative to the project root). version is the release-please
// manifest value embedded at build time, served via /api/version
// for the frontend's header chip.
//
// The server is intentionally minimal: a CORS-bypass proxy for the
// RD API, a healthz probe, a version endpoint, and the embedded
// static SPA. No server-side state — all pattern data lives in the
// user's browser localStorage.
func New(log *slog.Logger, webRoot fs.FS, version string) (*Server, error) {
	mux := http.NewServeMux()

	// /api/proxy — RD CORS workaround. See internal/proxy for the
	// hostname allowlist and security posture.
	proxyHandler := proxy.New(log)
	mux.Handle("/api/proxy", proxyHandler)
	mux.Handle("/api/proxy/", proxyHandler)

	// /api/version — plain text; fetched by the SPA on load to
	// render the version chip in the header.
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(version))
	})

	// /healthz — k8s probe.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Static assets served from the supplied FS.
	mux.Handle("/", http.FileServer(http.FS(webRoot)))

	return &Server{mux: mux, log: log}, nil
}

// ServeHTTP dispatches the request. ServeMux already handles
// longest-prefix routing; this method just delegates.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}
