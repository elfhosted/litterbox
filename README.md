# LitterBox 🐈‍⬛

> Spring-clean your Real-Debrid library.

LitterBox is a single-binary web app that signs you into Real-Debrid via
OAuth (no API key entry, no server-side storage), counts the broken /
dead / virus-flagged / error-state torrents in your library, and offers
a one-click bulk-delete with a type-to-confirm guard.

It exists because after RD's mass-banning event a lot of libraries
ended up full of unservable items, and the official UI's per-torrent
delete dance is brutal at scale.

## Trust model

- Your RD OAuth token lives in **your browser's `localStorage`** —
  never on our server beyond a stateless proxy that forwards your
  request to `api.real-debrid.com`.
- The proxy ([`internal/proxy/proxy.go`](internal/proxy/proxy.go))
  has a hostname allowlist and forwards only the `Authorization` +
  `Content-Type` headers. It never logs, persists, or inspects your
  token.
- The OAuth flow uses RD's well-known `X245A4XAIBGVM` "open_source"
  client ID — same one DebridMediaManager uses.

## Why a proxy at all

RD's REST API doesn't return CORS headers, so a browser-only SPA
can't call it directly. The proxy is a thin CORS bypass — it's not
doing auth, rate limiting, or storage on the server side. The
client-side rate limiter (240ms gap, 250 req/min, exponential-
backoff retry on 429/5xx) lives in [`web/static/app.js`](web/static/app.js).

## How the May 2026 filter is detected

Real-Debrid's May 2026 "infringing_file" filter doesn't surface on
the `/torrents` list — affected torrents report `status: "downloaded"`
just like healthy ones. Only `POST /unrestrict/link` reveals them
(HTTP 451 + `error_code: 35`). Probing every torrent is correct but
slow (~14h for a 10k library at RD's 250 req/min ceiling).

LitterBox uses a two-pass approach:

1. **Fast pass** — a baked-in filename regex that matches the
   release-naming patterns ElfHosted has already documented as
   filter-correlated (group tags, source markers like AMZN/WEB-DL,
   etc.). Free, instant, catches the bulk of the May 2026 class.
   Refined manually on each release from community-curated input
   (see below).

2. **Deep probe** — for the long tail the regex misses, the user
   can opt into a per-torrent `/unrestrict/link` walk that surfaces
   the ground-truth `451 + error_code 35` signal. Rate-limited
   client-side to 250 req/min; results cached in localStorage by
   hash so a re-scan doesn't re-probe known torrents.

Both passes feed the same broken set; the user chooses whether to
spend the time on phase 2 based on their library's stink rating.

## Community-curated regex updates

Every probe result also feeds a **client-side discovery analysis**:
the browser tokenizes each filename (release-shape fragments only —
group names, sources, encoders), aggregates per-token filtered-vs-
healthy counts in localStorage, and surfaces tokens that strongly
correlate with the May-2026 filter but aren't yet in the baked-in
regex.

When discovery turns up a candidate, the dashboard offers a
**"📋 Copy report for Reddit"** button — copies a pre-formatted
markdown snippet to the clipboard with the candidate tokens + the
user's filtered/healthy ratios for each. The user pastes it into
[our Reddit thread](https://www.reddit.com/r/elfhosted/) for the
community to review.

We watch the thread, periodically open a PR adding well-supported
candidates to the baked-in regex, and ship a new release. Manual,
visible, public — no database, no submission API, no operator
black-box. Nothing about a user's library ever leaves their browser
unless they explicitly post.

## Running locally

```sh
go build .
LISTEN=:8080 ./litterbox
# open http://localhost:8080
```

## Running in a container

```sh
docker build -t litterbox .
docker run -p 8080:8080 litterbox
```

## Environment

| Variable | Default | Notes |
| -------- | ------- | ----- |
| `LISTEN` | `:8080` | HTTP listen address |

No database, no secrets, no shared state. The server is purely a
static-asset host plus a CORS-bypass proxy.

## Deployment

This is the upstream source. ElfHosted runs LitterBox publicly at
[litterbox.elfhosted.com](https://litterbox.elfhosted.com)

## After LitterBox: migrate from Real-Debrid to TorBox

If your library scores high on the stink meter, the long-term
answer probably isn't another scoop. [ElfHosted's CatBox personal media stacks](https://store.elfhosted.com/product-category/personal-stacks/personal-media-stacks/?utm_source=litterbox&utm_medium=readme&utm_campaign=rd-migration)
provide a TorBox-backed personal media stack with a built-in
**Real-Debrid → TorBox migration path**: your existing library
transitions across rather than getting deleted. The migration is
API and policy compliant, fully endorsed by TorBox, and keeps the
same Sonarr / Radarr workflow you already use.

LitterBox cleans up what's already broken in your Real-Debrid
library; CatBox is the structural path off Real-Debrid without
losing what still works.

## License

MIT. See [LICENSE](LICENSE).
