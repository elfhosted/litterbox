// Package proxy implements the /api/proxy endpoint that forwards a
// single browser request to RealDebrid's API. Solves the CORS problem
// — RD's API doesn't return Access-Control-Allow-Origin headers, so
// a browser-only SPA can't talk to it directly.
//
// Security posture mirrors DMM's anticors.ts:
//
//   - Hostname allowlist. The browser supplies a target URL via
//     `?url=` query param OR a request body `target` field; the
//     proxy refuses any host that isn't in allowedHosts. Without
//     this an attacker could use the proxy as an SSRF springboard
//     against internal services.
//
//   - Authorization passthrough. The browser sets the Authorization
//     header to `Bearer <user's RD token>`; the proxy forwards it
//     to RD verbatim. The token is never logged, persisted, or
//     touched server-side beyond byte-level forwarding.
//
//   - No state. No session, no cookie, no in-memory token cache.
//     The user's localStorage is the single source of truth; the
//     proxy is purely a CORS bypass.
//
// Multi-replica safety: every request is fully self-contained — any
// replica can serve any request.
package proxy

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// allowedHosts is the set of hostnames the proxy will forward to.
// RD's two are present: `api.real-debrid.com` for the REST API and
// `api.real-debrid.com` (same host) for the OAuth device-code
// endpoints. Adding new hosts is a deliberate code change — never
// trust a client-supplied "I want to talk to X" without explicit
// allowlist entry.
var allowedHosts = map[string]bool{
	"api.real-debrid.com": true,
}

// upstreamTimeout caps each forwarded request. 30s gives RD's slower
// endpoints (/torrents pagination, /torrents/delete in bulk) room to
// respond while keeping a misbehaving upstream from pinning the
// goroutine indefinitely. The browser is doing its own
// rate-limited request stream, so this only fires on genuine slowness.
const upstreamTimeout = 30 * time.Second

// Handler is the http.Handler for /api/proxy. Constructed once at
// server init and reused for every request — every dependency is
// read-only.
type Handler struct {
	log    *slog.Logger
	client *http.Client
}

// New constructs the proxy handler. The underlying HTTP client uses
// the default transport (connection pooling included) with no global
// Timeout — per-request timeouts come from the upstreamTimeout
// context budget on each call.
func New(log *slog.Logger) *Handler {
	return &Handler{
		log: log,
		client: &http.Client{
			// No client-level Timeout: that would cap the whole
			// request including body read time. Use per-request
			// context.WithTimeout instead so the budget is explicit
			// and visible in tracing.
		},
	}
}

// ServeHTTP forwards one browser request to RD.
//
// Request shape: the browser issues `<METHOD> /api/proxy?url=<encoded
// upstream URL>` with the desired Authorization header and (for
// POST/DELETE) a request body. The proxy:
//
//  1. Validates the target URL parses and its hostname is allowlisted.
//  2. Builds an upstream request with the same method, body, and
//     headers (Authorization + Content-Type only — other headers
//     are dropped to avoid passing browser-specific noise like
//     Cookie / Referer).
//  3. Forwards. Copies the response status + body + a minimal set
//     of headers back to the browser.
//
// Failures are surfaced as JSON-shaped 4xx/5xx with a short reason
// the frontend can render directly.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	targetRaw := r.URL.Query().Get("url")
	if targetRaw == "" {
		http.Error(w, `{"error":"missing url parameter"}`, http.StatusBadRequest)
		return
	}
	target, err := url.Parse(targetRaw)
	if err != nil || target.Scheme != "https" || target.Host == "" {
		http.Error(w, `{"error":"invalid target url (must be absolute https)"}`, http.StatusBadRequest)
		return
	}
	if !allowedHosts[strings.ToLower(target.Host)] {
		// Don't echo the hostname back — keeps the proxy from
		// signaling probe attempts. Log it for the operator.
		h.log.Warn("proxy: refused unlisted host", "host", target.Host, "remote", r.RemoteAddr)
		http.Error(w, `{"error":"target host not allowed"}`, http.StatusForbidden)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), upstreamTimeout)
	defer cancel()

	upstream, err := http.NewRequestWithContext(ctx, r.Method, target.String(), r.Body)
	if err != nil {
		h.log.Warn("proxy: build upstream request failed", "err", err)
		http.Error(w, `{"error":"upstream request build failed"}`, http.StatusInternalServerError)
		return
	}
	// Forward only the headers RD actually needs. Cookie / Referer /
	// Origin etc. would just confuse RD's auth path and leak browser
	// state we don't need to expose.
	if auth := r.Header.Get("Authorization"); auth != "" {
		upstream.Header.Set("Authorization", auth)
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		upstream.Header.Set("Content-Type", ct)
	}
	upstream.Header.Set("User-Agent", "litterbox/0.1 (https://github.com/elfhosted/litterbox)")

	resp, err := h.client.Do(upstream)
	if err != nil {
		h.log.Warn("proxy: upstream call failed", "host", target.Host, "err", err)
		http.Error(w, `{"error":"upstream call failed"}`, http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read the body before forwarding so we can both log it on
	// non-2xx (small RD error envelopes) AND propagate it intact.
	// Bounded at 16MB to defend against a misbehaving upstream
	// returning a giant body. The double-buffer cost is irrelevant
	// for RD payloads (all JSON, all small).
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))

	// Log upstream non-success responses so a 5xx pattern is
	// debuggable from the server side. Path-only (no query) keeps
	// tokens out of the log.
	if resp.StatusCode >= 400 && resp.StatusCode != http.StatusNotFound &&
		resp.StatusCode != 451 && resp.StatusCode != 401 && resp.StatusCode != 403 {
		snippet := body
		if len(snippet) > 256 {
			snippet = snippet[:256]
		}
		h.log.Warn("proxy: upstream non-2xx",
			"host", target.Host,
			"path", target.Path,
			"method", r.Method,
			"status", resp.StatusCode,
			"body_preview", string(snippet))
	}

	// Propagate the response.
	for _, h := range []string{"Content-Type", "Content-Length", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(body)
}
