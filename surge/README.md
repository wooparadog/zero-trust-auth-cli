# Surge integration (no daemon, no manual editing)

Surge integration is **opt-in**: pass `-surge-dir DIR` to `login` and the
CLI writes two artifacts into `DIR` (typically the folder Surge loads
modules from, e.g. `/path/to/SurgeProfiles`). Omit the flag and the CLI just
writes `token.env` like before.

```
<surge-dir>/
├── cf-zero-trust.js               # http-request script — BOOTSTRAP map is INLINED
└── cf-zero-trust.sgmodule         # Surge module: [MITM] + [Script] with absolute script-path
```

`cf-zero-trust.js` is **self-contained**: the bootstrap data
(`refresh_token` / `client_id` / `token_endpoint` / `resource` per origin)
lives inside the script as `const BOOTSTRAP = {…};`. No `require()`, no
companion JSON file — so the script keeps working no matter what directory
Surge actually invokes it from.

Re-running `login` for another origin parses the existing `const BOOTSTRAP`
out of `cf-zero-trust.js`, merges in the new entry, and regenerates both files
with the union of hostnames.

No `require()`, no `BOOTSTRAP_PATH` constant to edit, no manual paste into
Surge's persistent store, no background daemon — the inlined `const BOOTSTRAP`
*is* the source.

```
First time / on re-login:                Every request:

  zero-trust-auth-cli login <url>          Surge MITM ─► cf-zero-trust.js
            │                                                │ const BOOTSTRAP[origin]
            ▼                                                ▼ cache valid?
   <surge-dir>/cf-zero-trust.js   (rewritten   yes ─► inject  cf-access-token: <token>
   <surge-dir>/cf-zero-trust.sgmodule   each   no  ─► POST token_endpoint
                                    login)         grant_type=refresh_token
                                                   cache → $persistentStore
                                                   inject
```

The injected header is **`cf-access-token: <access_token>`** (raw token value,
no `Bearer ` prefix), matching what Cloudflare Access expects.

## Setup

1. **Authorize once per protected origin** (this opens a browser). Pass
   `-surge-dir` to also drop the Surge artifacts into Surge's module folder;
   omit it if you don't want Surge integration this run.

   ```sh
   zero-trust-auth-cli login \
     -surge-dir /path/to/SurgeProfiles \
     https://your-protected.example.com
   ```

   Output:

   ```
   Wrote sourceable token file: …/token.env
   Load it with: . '…/token.env'

   ────────────────────────────── Surge ──────────────────────────────
     script:    /path/to/SurgeProfiles/cf-zero-trust.js
     sgmodule:  /path/to/SurgeProfiles/cf-zero-trust.sgmodule

     Next steps:
       1. First time only — Surge → More → Modules → enable
          `Cloudflare Zero Trust Access Auto Auth`.
       2. After every login — reload Surge so the updated BOOTSTRAP
          takes effect (Surge menu bar → Reload, or restart Surge).
   ────────────────────────────────────────────────────────────────────
   ```

2. **Install the generated `cf-zero-trust.sgmodule`** in Surge (drag/drop, or
   point Surge at the absolute path the CLI printed). It already contains:
   - the absolute `script-path` to `cf-zero-trust.js`,
   - a `hostname` list with the host of every origin you've `login`'d,
   - a single regex `pattern` matching that host union.

   Make sure Surge's MITM CA is trusted on the protected hosts — otherwise
   it cannot modify request headers in HTTPS traffic.

That's the whole setup. Re-running `login` (e.g., to add another origin or
after a `refresh_token` revocation) rewrites all three artifacts; Surge picks
them up on the next profile reload.

## What persists where

| Where | What | Lifetime |
|---|---|---|
| `cf-zero-trust.js` `const BOOTSTRAP` (CLI-written) | `refresh_token`, `client_id`, `token_endpoint`, `resource` per origin. Re-login parses and merges this block in place. | Until next `login` rewrites the file |
| `$persistentStore` key `cf_zero_trust_<origin>` (Surge-written) | Cached `access_token`, `expires_at`, optionally a rotated `refresh_token` | Across requests; invalidated when the inlined `refresh_token` changes |

If your Cloudflare authorization server rotates `refresh_token` on each
refresh, the rotated value is kept in `$persistentStore` so subsequent
refreshes use the latest one. A fresh `login` rotates the file's value,
which the script detects (via a `bootstrap_seed` field) and resets the
cache.

## First-time-use notifications

`cf-zero-trust.js` posts a Surge notification (`$notification.post`) for these
states, rate-limited to once per 30 minutes per (origin, kind):

| Trigger | Body |
|---|---|
| No `BOOTSTRAP[origin]` entry in the inlined map | "Run `zero-trust-auth-cli login <origin>` and reload the Surge module" |
| Refresh returned HTTP error | "Re-run `zero-trust-auth-cli login <origin>`" |
| Refresh failed at the network layer | The underlying error string. |

## Caveats

- After re-running `login`, reload the Surge profile so it re-reads
  `cf-zero-trust.js`. The script handles this gracefully — `$persistentStore`
  cache is keyed by `bootstrap_seed`, so stale entries are dropped when the
  inlined `refresh_token` changes.
- The CLI must run on the device that has Surge installed (so the absolute
  `script-path` in `cf-zero-trust.sgmodule` resolves on that device). For iOS
  Surge, sync the generated files to the device (Files / iCloud Drive).
- The OAuth `token_endpoint` must be reachable through whatever proxy Surge
  is currently using. `$httpClient.post` goes out the same way as normal
  Surge traffic.
- One entry per origin (scheme + host). Different paths on the same host
  share an entry.
