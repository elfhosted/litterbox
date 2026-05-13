// Package proxy implements the /api/proxy endpoint that forwards a
// single browser request to RealDebrid's API. Solves the CORS problem
// — RD's API doesn't return Access-Control-Allow-Origin headers, so
// a browser-only SPA can't talk to it directly.
//
// Security posture mirrors DMM's anticors.ts:
//
//   - Hostname allowlist. The browser supplies a target URL via the
//     `?url=` query param; the proxy refuses any host that isn't in
//     allowedHosts. Without this an attacker could use the proxy as
//     an SSRF springboard against internal services.
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
	"bytes"
	"context"
	"encoding/json"
	"hash/fnv"
	"io"
	"log/slog"
	"math/rand"
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
	log               *slog.Logger
	clients           []*http.Client // 1 entry when no outbound proxies; N when configured
	overrideUserAgent string         // when non-empty, replaces the browser's UA on every outbound
}

// New constructs the proxy handler. outboundProxies is a list of
// upstream-proxy URLs (e.g. "http://user:pass@residential-rotator:8080");
// each is wired into its own http.Client and the handler picks one
// at random per request to spread the load across multiple egress
// IPs. RD rate-limits per source IP, so with all litterbox replicas
// going out from the same k8s egress, concurrent sign-ins hit 429
// quickly; outbound proxies dilute that. Empty/nil list = direct.
//
// User-Agent forwarding: by default the proxy forwards whatever UA
// the browser sent (the most honest representation — we're CORS-
// bypassing a browser request). overrideUserAgent, when non-empty,
// replaces it on every outbound request. Useful when RD's WAF
// extends from app-fingerprint matching ("litterbox/X.Y.Z" → 451) to
// broader UA filtering — operator can flip to "curl/8.7.1" or
// similar (StremThru's recent move) without a rebuild.
func New(log *slog.Logger, outboundProxies []string, overrideUserAgent string) *Handler {
	clients := make([]*http.Client, 0, max(1, len(outboundProxies)))
	if len(outboundProxies) == 0 {
		// No client-level Timeout: that would cap the whole request
		// including body read time. Use per-request
		// context.WithTimeout instead so the budget is explicit and
		// visible in tracing.
		clients = append(clients, &http.Client{})
	} else {
		for _, raw := range outboundProxies {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			pu, err := url.Parse(raw)
			if err != nil {
				log.Warn("proxy: skipping invalid outbound proxy URL", "raw", raw, "err", err)
				continue
			}
			clients = append(clients, &http.Client{
				Transport: &http.Transport{
					Proxy: http.ProxyURL(pu),
				},
			})
		}
		if len(clients) == 0 {
			log.Warn("proxy: OUTBOUND_PROXIES set but no usable URLs; falling back to direct")
			clients = append(clients, &http.Client{})
		}
	}
	log.Info("proxy: outbound transport configured",
		"client_count", len(clients),
		"user_agent_override", overrideUserAgent != "")
	return &Handler{log: log, clients: clients, overrideUserAgent: overrideUserAgent}
}

// pickClient returns the outbound client for this request. When an
// Authorization header is present, the choice is *deterministic*:
// hash(authHeader) % N. Same token → same egress, every time.
//
// Rationale: RD's anti-abuse layer flags tokens used from many IPs
// in a short window — looks like credential theft to them. Random
// per-request egress selection (the previous behavior) accelerated
// that flagging, because a single user's sign-in + dashboard would
// touch N different proxybase IPs per minute. Sticky-per-token
// gives RD a consistent IP per user-token, which is what they
// expect for normal traffic. Load still spreads because different
// users' tokens hash to different egresses.
//
// Anonymous requests (no Authorization header) fall back to random
// pick — there's no token to anchor the hash to and nothing to
// burn either.
func (h *Handler) pickClient(authHeader string) *http.Client {
	if len(h.clients) == 1 {
		return h.clients[0]
	}
	if authHeader == "" {
		return h.clients[rand.Intn(len(h.clients))]
	}
	hash := fnv.New32a()
	_, _ = hash.Write([]byte(authHeader))
	return h.clients[hash.Sum32()%uint32(len(h.clients))]
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

	// Buffer the request body upfront so we can replay it on retry.
	// 16MB cap mirrors the response-side limit; RD's POST bodies are
	// tiny (form-encoded auth, magnet add, etc).
	var reqBody []byte
	if r.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(r.Body, 16<<20))
		r.Body.Close()
	}

	// Retry only on transport errors (proxy hiccups, dropped TCP).
	// Do NOT retry on HTTP 451: that's RD's anti-abuse signal, and
	// retrying with a different egress IP makes the same token
	// authenticate from N different IPs in seconds — which is
	// exactly the credential-theft pattern RD's heuristic flags.
	// We were burning user tokens within one sign-in attempt that
	// way. Empirical confirmation: a single sign-in with retry=3
	// took a freshly-regenerated RD API token from "200 OK from any
	// IP" to "451 from every IP" in under 10 seconds.
	maxAttempts := 1
	if len(h.clients) > 1 {
		maxAttempts = 3
	}
	authHeader := r.Header.Get("Authorization")
	var resp *http.Response
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		var bodyReader io.Reader
		if len(reqBody) > 0 {
			bodyReader = bytes.NewReader(reqBody)
		}
		upstream, buildErr := http.NewRequestWithContext(ctx, r.Method, target.String(), bodyReader)
		if buildErr != nil {
			h.log.Warn("proxy: build upstream request failed", "err", buildErr)
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
		// User-Agent: default is to forward the browser's verbatim (most
		// honest representation — we're CORS-bypassing a browser request).
		// If overrideUserAgent is set (OUTBOUND_USER_AGENT env), replace it
		// on every outbound. Operator-rotatable hedge against RD's WAF
		// extending to broader UA filtering.
		switch {
		case h.overrideUserAgent != "":
			upstream.Header.Set("User-Agent", h.overrideUserAgent)
		default:
			if ua := r.Header.Get("User-Agent"); ua != "" {
				upstream.Header.Set("User-Agent", ua)
			}
		}

		resp, err = h.pickClient(authHeader).Do(upstream)
		if attempt >= maxAttempts {
			break
		}
		if err != nil {
			h.log.Info("proxy: transport error, retrying with different egress",
				"attempt", attempt, "host", target.Host, "path", target.Path, "err", err)
			continue
		}
		break
	}
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

	// Log upstream non-success responses. Filter out the noisy-but-
	// expected cases:
	//   - 404 anywhere (normal not-found; e.g. /torrents/info/{id}
	//     after a delete races with a poll)
	//   - 451 on /unrestrict/link (the documented infringing_file
	//     signal — fires for every filtered torrent during a deep
	//     probe, so it's high-volume + already exposed to the user
	//     via the discovery results)
	// Everything else is interesting:
	//   - 451 on /oauth/v2/* or /rest/1.0/* = WAF/IP-reputation
	//     blocking us, not a user error
	//   - 401/403 = token problem, useful when debugging
	//   - 429 = rate-limited, useful for capacity planning
	//   - 5xx = upstream problem
	// Path-only (no query) keeps tokens out of the log.
	noise := resp.StatusCode == http.StatusNotFound ||
		(resp.StatusCode == 451 && target.Path == "/rest/1.0/unrestrict/link")
	if !noise && resp.StatusCode >= 400 {
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

	// For certain API requests RD returns 451 and prepends an error
	// JSON before the real response body:
	//   {"error":"permission_denied","error_code":9}{"id":...}
	// Strip the prefix and return 200 when the second JSON token is a
	// clean success (no "error" key) or an array. Genuine 451s from
	// /unrestrict/link (error_code 35, infringing-file filter) contain
	// only one JSON object and are left untouched. Belt-and-braces
	// against RD's WAF — the UA-forward fix should mostly prevent the
	// double-JSON case, but this handles the residual.
	// Contributed by @andesco in PR #7.
	statusCode := resp.StatusCode
	if statusCode == 451 {
		if real, ok := extractRealBody(body); ok {
			body = real
			statusCode = http.StatusOK
		}
	}

	// Propagate the response.
	for _, h := range []string{"Content-Type", "Content-Length", "Retry-After"} {
		if v := resp.Header.Get(h); v != "" {
			w.Header().Set(h, v)
		}
	}
	// Content-Length may no longer match after stripping the WAF prefix.
	if statusCode != resp.StatusCode {
		w.Header().Del("Content-Length")
	}
	w.WriteHeader(statusCode)
	_, _ = w.Write(body)
}

// extractRealBody detects RD's double-JSON pattern and returns the
// second token when it is a success object (no "error" key) or an
// array. Walks the first JSON object with brace counting + escape
// handling so it's robust to strings containing braces.
func extractRealBody(body []byte) ([]byte, bool) {
	depth, inStr, escaped := 0, false, false
	for i, b := range body {
		switch {
		case escaped:
			escaped = false
		case b == '\\' && inStr:
			escaped = true
		case b == '"':
			inStr = !inStr
		case inStr:
			// inside a string literal — ignore braces
		case b == '{':
			depth++
		case b == '}':
			depth--
			if depth == 0 {
				rest := bytes.TrimSpace(body[i+1:])
				if len(rest) == 0 {
					return nil, false
				}
				if rest[0] == '[' {
					return rest, true
				}
				if rest[0] == '{' {
					var check map[string]json.RawMessage
					if err := json.Unmarshal(rest, &check); err != nil {
						return nil, false
					}
					if _, hasErr := check["error"]; hasErr {
						return nil, false
					}
					return rest, true
				}
				return nil, false
			}
		}
	}
	return nil, false
}
