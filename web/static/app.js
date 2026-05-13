// litterbox frontend — vanilla JS, ~200 lines, no framework.
//
// Responsibilities:
//   1. OAuth device-code flow against Real-Debrid (same well-known
//      open_source client id DMM uses).
//   2. Stash + retrieve the token in localStorage.
//   3. On the dashboard, paginate /torrents and tally broken vs healthy.
//   4. On user confirmation, bulk-delete the broken ones with
//      client-side rate limiting (240ms per call ≈ 250 req/min, the
//      RD documented ceiling) and exponential-backoff retry on 429/5xx.
//
// Every RD API call goes via our own /api/proxy (CORS bypass — see
// internal/proxy/proxy.go). The token never crosses the network in
// plaintext anywhere except inside the Authorization header of that
// proxied request.

(function () {
  "use strict";

  // The well-known "open_source" client id Real-Debrid publishes for
  // installed/web apps. Same one DMM uses. No client secret, no app
  // registration required.
  const CLIENT_ID = "X245A4XAIBGVM";

  // RD API base. Every call is rewritten through /api/proxy?url=...
  // by the proxiedFetch wrapper below.
  const RD = "https://api.real-debrid.com";

  // localStorage keys. Names mirror DMM so a user juggling both apps
  // gets predictable behaviour (one app's sign-in doesn't auth the
  // other, but the key shape is familiar).
  const LS = {
    accessToken: "rd:accessToken",
    refreshToken: "rd:refreshToken",
    expiresAt: "rd:expiresAt", // unix ms
  };

  // RD's documented rate limit. 240ms gap = 250 req/min — same value
  // DMM enforces, same threshold RD honours.
  const MIN_REQUEST_INTERVAL_MS = 240;

  // ============================================================
  // Proxied fetch with client-side rate limiting + 429/5xx retry.
  // ============================================================

  let _lastRequestAt = 0;

  // proxiedFetch enforces the MIN_REQUEST_INTERVAL_MS gap between
  // RD calls. Earlier versions used a global promise chain for
  // serialization, but every caller in litterbox already issues
  // sequential `await`-d calls — the chain was redundant AND it
  // leaked memory: each .then() link held a closure over the prior
  // link, so the chain grew O(N) in the number of calls and the
  // browser visibly slowed past ~100-200 in-flight rate-limited
  // calls (field report on a 250-torrent deep probe).
  //
  // The inherent serialization of `await` is the only ordering
  // guarantee we need; the gate timestamp catches the rare case
  // where two independent code paths happen to fire at the same
  // moment.
  async function proxiedFetch(rdPath, opts = {}) {
    const wait = Math.max(0, _lastRequestAt + MIN_REQUEST_INTERVAL_MS - Date.now());
    if (wait > 0) await sleep(wait);
    _lastRequestAt = Date.now();
    // Pass opts through unchanged so callers can supply an
    // onRetry({reason, attempt, backoffMs}) hook to surface
    // mid-retry waits to the UI ("rate-limited, backing off 16s…").
    // Without this the deep-probe loop appears frozen during a
    // long 429 backoff.
    return doProxied(rdPath, opts, 0);
  }

  // Per-fetch timeout. Defends against a single RD endpoint that
  // stops responding (or a stuck CORS proxy hop) from hanging the
  // whole probe loop indefinitely. 30s is generous for any
  // /unrestrict/link call — RD typically responds in <2s, and the
  // 451 hit (the case we care about) is even faster because RD
  // shortcuts before any download starts.
  const PER_FETCH_TIMEOUT_MS = 30000;

  async function doProxied(rdPath, opts, attempt) {
    const url = `/api/proxy?url=${encodeURIComponent(RD + rdPath)}`;
    const headers = Object.assign({}, opts.headers || {});
    const token = localStorage.getItem(LS.accessToken);
    if (token && !headers.Authorization) {
      headers.Authorization = `Bearer ${token}`;
    }
    // AbortSignal.timeout (widely supported as of 2023) gives us a
    // declarative per-call timeout without managing a controller
    // by hand. Throws DOMException("aborted") on expiry, which the
    // caller's try/catch handles as a normal error.
    let resp;
    try {
      resp = await fetch(url, Object.assign({}, opts, {
        headers,
        signal: AbortSignal.timeout(PER_FETCH_TIMEOUT_MS),
      }));
    } catch (e) {
      // Network error OR timeout. Treat 5xx-like — retry with
      // backoff. After the retry budget we re-throw so the
      // caller's outer catch can record an error and move on.
      if (attempt >= 6) throw e;
      const backoff = Math.min(60000, Math.pow(2, attempt) * 1000);
      if (opts.onRetry) opts.onRetry({ reason: "network", attempt, backoffMs: backoff });
      await sleep(backoff);
      return doProxied(rdPath, opts, attempt + 1);
    }
    if (resp.status === 429 || (resp.status >= 500 && resp.status < 600)) {
      // Stable error codes — RD's response body tells us this is
      // NOT a transient API issue. Retrying just wastes time. The
      // 7-attempt budget would otherwise burn ~2min per row.
      // Known stable codes:
      //   19  hoster_unavailable        — file host's CDN is down
      //   23  hoster_in_maintenance     — host's planned downtime
      // The caller treats these as a different outcome ("dead-link",
      // distinct from "filtered" and "healthy") in the probe loop.
      let stable = false;
      try {
        const text = await resp.clone().text();
        const j = JSON.parse(text);
        if (j.error_code === 19 || j.error_code === 23) stable = true;
      } catch { /* not JSON / non-RD body → retry as usual */ }
      if (stable) return resp;

      if (attempt >= 6) return resp; // give up after ~60s of backoff
      const retryAfter = parseFloat(resp.headers.get("Retry-After") || "0");
      const backoff = retryAfter > 0
        ? retryAfter * 1000
        : Math.min(60000, Math.pow(2, attempt) * 1000);
      if (opts.onRetry) opts.onRetry({ reason: resp.status === 429 ? "rate-limit" : "5xx", attempt, backoffMs: backoff });
      await sleep(backoff);
      return doProxied(rdPath, opts, attempt + 1);
    }
    return resp;
  }

  function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

  // ============================================================
  // OAuth device-code flow.
  // ============================================================
  //
  // RD documents three calls:
  //   1. GET /oauth/v2/device/code?client_id=...&new_credentials=yes
  //      → returns { device_code, user_code, verification_url, ... }
  //   2. POST /oauth/v2/device/credentials?client_id=...&code=<device_code>
  //      → poll until it returns { client_id, client_secret }
  //   3. POST /oauth/v2/token with grant_type=http://oauth.net/grant_type/device/1.0
  //      → returns { access_token, refresh_token, expires_in }
  //
  // (Yes, step 2 returns a "client_secret" — that's RD's naming for
  // the per-user secret used in step 3. It's user-bound, not app-bound.)

  async function startDeviceAuth() {
    const r = await proxiedFetch(
      `/oauth/v2/device/code?client_id=${CLIENT_ID}&new_credentials=yes`
    );
    if (!r.ok) throw new Error(`device code start: ${r.status}`);
    return r.json();
  }

  async function pollDeviceCredentials(deviceCode) {
    const r = await proxiedFetch(
      `/oauth/v2/device/credentials?client_id=${CLIENT_ID}&code=${encodeURIComponent(deviceCode)}`
    );
    if (r.status === 403) return null; // user hasn't confirmed yet
    if (!r.ok) throw new Error(`device credentials: ${r.status}`);
    return r.json(); // { client_id, client_secret }
  }

  async function exchangeForToken(userClientId, userClientSecret, deviceCode) {
    const body = new URLSearchParams({
      client_id: userClientId,
      client_secret: userClientSecret,
      code: deviceCode,
      grant_type: "http://oauth.net/grant_type/device/1.0",
    });
    const r = await proxiedFetch(`/oauth/v2/token`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!r.ok) throw new Error(`token exchange: ${r.status}`);
    return r.json(); // { access_token, refresh_token, expires_in, ... }
  }

  function persistTokenResponse(tok) {
    localStorage.setItem(LS.accessToken, tok.access_token);
    if (tok.refresh_token) localStorage.setItem(LS.refreshToken, tok.refresh_token);
    if (tok.expires_in) {
      localStorage.setItem(LS.expiresAt, String(Date.now() + tok.expires_in * 1000));
    }
  }

  // Landing-page entry point. Wired below in the DOMContentLoaded
  // handler; orchestrates the device-code flow start to finish.
  //
  // RD's device flow is OOB — there's no redirect_uri — but DMM
  // discovered that RD's /device page accepts a POST with `usercode`
  // and `action=Continue` and renders the "Authorize?" confirmation
  // directly. So we POST the code on the user's behalf via a hidden
  // form submission: one click, no copy/paste. The manual code +
  // copy button is retained as a fallback under a disclosure, in
  // case RD changes the endpoint behaviour. Polling auto-bounces
  // the user to /dashboard.html once the approve lands.
  async function runDeviceAuthFlow(statusEl) {
    statusEl.textContent = "Asking Real-Debrid for a sign-in code…";
    const codeResp = await startDeviceAuth();
    // codeResp: { device_code, user_code, verification_url, interval }

    const code = escapeHTML(codeResp.user_code);
    const vurl = escapeHTML(codeResp.verification_url);
    statusEl.innerHTML = `
      <div class="oauth-panel">
        <p class="oauth-step">Click to confirm at Real-Debrid (no typing needed):</p>
        <form method="post" action="https://real-debrid.com/device" target="_blank" class="oauth-form">
          <input type="hidden" name="usercode" value="${code}">
          <input type="hidden" name="action" value="Continue">
          <input type="hidden" name="deviceName" value="LitterBox | ElfHosted">
          <button type="submit" class="oauth-open">🔗 Approve LitterBox at Real-Debrid</button>
        </form>
        <p class="muted small oauth-poll">⏳ Waiting for confirmation — we'll bounce you to your dashboard the moment you approve.</p>
        <details class="oauth-fallback">
          <summary class="muted small">Button didn't work? Paste this code manually instead.</summary>
          <p class="muted small">Open <a href="${vurl}" target="_blank" rel="noopener">${vurl}</a> and paste:</p>
          <div class="oauth-code-row">
            <code class="oauth-code">${code}</code>
            <button type="button" class="oauth-copy" id="oauth-copy">📋 Copy</button>
          </div>
        </details>
      </div>`;

    // Best-effort auto-copy in case the user falls back to the
    // manual disclosure. Swallow errors silently — the Copy button
    // below handles the explicit case if writeText was blocked.
    try { await navigator.clipboard.writeText(codeResp.user_code); } catch (_) {}

    const copyBtn = document.getElementById("oauth-copy");
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(codeResp.user_code);
        const orig = copyBtn.textContent;
        copyBtn.textContent = "✓ copied";
        setTimeout(() => { copyBtn.textContent = orig; }, 1200);
      } catch (_) {
        alert("Couldn't reach the clipboard — select and copy the code manually.");
      }
    });

    const pollEvery = Math.max(2, (codeResp.interval || 5)) * 1000;
    const expiresAt = Date.now() + (codeResp.expires_in || 600) * 1000;

    while (Date.now() < expiresAt) {
      await sleep(pollEvery);
      const creds = await pollDeviceCredentials(codeResp.device_code);
      if (creds) {
        const poll = document.querySelector(".oauth-poll");
        if (poll) poll.textContent = "✓ Code accepted — fetching your token…";
        const tok = await exchangeForToken(creds.client_id, creds.client_secret, codeResp.device_code);
        persistTokenResponse(tok);
        // Redirect to dashboard. The dashboard expects an access token
        // in localStorage and renders itself from there.
        window.location.href = "/dashboard.html";
        return;
      }
    }
    throw new Error("Sign-in window expired — refresh and try again.");
  }

  // ============================================================
  // Page wiring.
  // ============================================================

  // Inject a persistent sign-out link into the page header whenever
  // a token is present in localStorage. Same code path on every page
  // so the affordance is always-visible, never buried in a sub-flow
  // (the user's #1 piece of feedback after their first end-to-end
  // run was "I can only sign out from the done screen").
  //
  // Idempotent — guarded by id="header-signout" so a re-run (e.g.
  // after a hot-reload) doesn't double up. Click handler clears
  // localStorage and bounces to /, which the landing page's own
  // signin-button check then renders as the not-signed-in state.
  function mountSignout() {
    if (!localStorage.getItem(LS.accessToken)) return;
    if (document.getElementById("header-signout")) return;
    const header = document.querySelector("header");
    if (!header) return;
    const a = document.createElement("a");
    a.id = "header-signout";
    a.href = "#";
    a.className = "header-signout muted small";
    a.textContent = "Sign out";
    a.addEventListener("click", (e) => {
      e.preventDefault();
      localStorage.removeItem(LS.accessToken);
      localStorage.removeItem(LS.refreshToken);
      localStorage.removeItem(LS.expiresAt);
      window.location.href = "/";
    });
    header.appendChild(a);
  }

  // Best-effort version fetch — populates the #app-version chip in
  // the header on every page. Server bakes the value in from the
  // release-please manifest at build time. Silent on failure (dev
  // build serving without /api/version, transient outage, etc.).
  async function mountVersion() {
    const el = document.getElementById("app-version");
    if (!el) return;
    try {
      const r = await fetch("/api/version", { cache: "no-store" });
      if (!r.ok) return;
      const v = (await r.text()).trim();
      if (!v) return;
      el.textContent = `v${v}`;
    } catch (_) { /* swallow */ }
  }

  document.addEventListener("DOMContentLoaded", () => {
    mountSignout();
    mountVersion();

    // Landing page: if already signed in, skip straight to dashboard.
    const signinBtn = document.getElementById("signin-button");
    if (signinBtn) {
      if (localStorage.getItem(LS.accessToken)) {
        window.location.href = "/dashboard.html";
        return;
      }
      const status = document.getElementById("signin-status");
      signinBtn.addEventListener("click", async () => {
        signinBtn.disabled = true;
        try {
          await runDeviceAuthFlow(status);
        } catch (err) {
          status.innerHTML = `<span class="warn">Sign-in failed:</span> ${escapeHTML(err.message)}`;
          signinBtn.disabled = false;
        }
      });
    }

    // Dashboard page: render lives in dashboard.html's inline script
    // because it depends on DOM elements unique to that page. The
    // shared API surface (proxiedFetch + token lifecycle) is here.
    if (document.body.dataset.page === "dashboard") {
      // Defer to the inline initDashboard() call on that page.
      window.litterbox = { proxiedFetch, LS, sleep, escapeHTML };
    }
  });

  function escapeHTML(s) {
    return String(s).replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
  }

  // Expose the rate-limited proxied fetch for the dashboard page's
  // inline script to use.
  window.litterbox = window.litterbox || { proxiedFetch, LS, sleep, escapeHTML };
})();
