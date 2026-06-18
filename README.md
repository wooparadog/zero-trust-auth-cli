# zero-trust-auth-cli

`zero-trust-auth-cli` logs in to a Cloudflare Access protected resource through Cloudflare Zero Trust Managed OAuth and writes the result as a sourceable per-host shell file.

The command:

1. Discovers the protected resource metadata.
2. Reads Cloudflare's hosted OAuth authorization server metadata.
3. Starts a local loopback callback server on a random port.
4. Dynamically registers a public OAuth client for that callback.
5. Prints the authorization URL and opens the browser when appropriate.
6. Receives the callback through the local server, or accepts the pasted localhost redirect URL on stdin.
7. Exchanges the callback code for an access token.
8. Writes shell exports to a private per-host token file and updates a global loader.

The `renew` command uses the saved refresh token to fetch a new access token without opening a browser. Cloudflare controls the maximum token lifetimes in the Access application's Managed OAuth settings; once the refresh-token grant session expires, run `login` again.

## Install

```sh
go install github.com/wooparadog/zero-trust-auth-cli@latest
```

From this checkout:

```sh
go build .
```

## Login

```sh
zero-trust-auth-cli login https://example.com
. "$(zero-trust-auth-cli config-path)/tokens/example.com.env"

curl -H "$CF_ACCESS_AUTHORIZATION_HEADER" https://example.com
```

`login` prints the Cloudflare authorization URL, starts a localhost callback server on a random port, exchanges the returned authorization code for tokens, writes `tokens/<host>.env`, and updates `tokens.env`, a global loader that sources every per-host token file.

When the token file is sourced, it checks `CF_ACCESS_TOKEN_EXPIRES_AT_UNIX`. If the access token is expired and `zero-trust-auth-cli` is available in `PATH`, the file automatically runs:

```sh
zero-trust-auth-cli renew -out "$CF_ACCESS_TOKEN_FILE"
```

After a successful renewal, it reloads the updated token file so the current shell gets the new access token.

## Remote SSH Login

When running from a remote SSH session, copy the printed authorization URL into your local browser. After Cloudflare redirects to the localhost callback URL, the browser may fail to connect because the callback server is on the remote host.

Copy the final URL from your browser address bar:

```text
http://127.0.0.1:12345/callback?code=...&state=...
```

Paste that URL into the waiting CLI and press Enter. The localhost server remains active at the same time, so normal non-SSH browser callbacks still work.

## Renew

```sh
zero-trust-auth-cli renew "$(zero-trust-auth-cli config-path)/tokens/example.com.env"
. "$(zero-trust-auth-cli config-path)/tokens/example.com.env"
```

`renew` reads `CF_ACCESS_REFRESH_TOKEN`, `CF_ACCESS_CLIENT_ID`, and `CF_ACCESS_TOKEN_ENDPOINT` from the token file, then rewrites the same file with a new access token. If Cloudflare rotates the refresh token, the new value is saved. If Cloudflare does not return a refresh token during `login`, `login` fails and you will need to check the Access application's Managed OAuth settings.

If automatic renewal fails while sourcing the token file, the shell prints a suggested `zero-trust-auth-cli login ...` command. It does not run login automatically.

## Verbose Diagnostics

Use `-verbose` to print the raw token endpoint response to stderr:

```sh
zero-trust-auth-cli login -verbose https://example.com
zero-trust-auth-cli renew -verbose "$(zero-trust-auth-cli config-path)/tokens/example.com.env"
```

This output includes access tokens and any refresh token returned by Cloudflare. Treat it as secret and avoid saving it in shell history, CI logs, or issue trackers.

## Token Files

By default, token files are stored below Go's `os.UserConfigDir()`:

- Linux: `$XDG_CONFIG_HOME/zero-trust-auth-cli` or `$HOME/.config/zero-trust-auth-cli`
- macOS: `$HOME/Library/Application Support/zero-trust-auth-cli`

Each per-host token file is written with mode `0600` and contains exports such as:

```sh
export CF_ACCESS_TOKEN='oauth:...'
export CF_ACCESS_REFRESH_TOKEN='oauth:...'
export CF_ACCESS_TOKEN_EXPIRES_AT='2026-04-25T01:17:03Z'
export CF_ACCESS_TOKEN_EXPIRES_AT_UNIX='1777079823'
export CF_ACCESS_BEARER='Bearer oauth:...'
export CF_ACCESS_AUTHORIZATION_HEADER='Authorization: Bearer oauth:...'
export CF_SITE_ACCESS_TOKEN_EXAMPLE_COM='oauth:...'
export CF_SITE_ACCESS_BEARER_EXAMPLE_COM='Bearer oauth:...'
export CF_SITE_ACCESS_AUTHORIZATION_HEADER_EXAMPLE_COM='Authorization: Bearer oauth:...'
export CF_ACCESS_TOKEN_FILE='/home/alice/.config/zero-trust-auth-cli/tokens/example.com.env'
```

To load all saved tokens automatically in new shells, add this to `~/.zshrc`, `~/.bashrc`, or your shell's equivalent startup file:

```sh
[[ -s "$HOME/.config/zero-trust-auth-cli/tokens.env" ]] && source "$HOME/.config/zero-trust-auth-cli/tokens.env"
```

On macOS, replace the path with the location printed by:

```sh
zero-trust-auth-cli config-path
```

## Build

```sh
make test
make release
```

`make release` writes cross-compiled binaries to `dist/`:

```text
zero-trust-auth-cli-windows-amd64.exe
zero-trust-auth-cli-darwin-arm64
zero-trust-auth-cli-linux-amd64
```

## Flags

```sh
zero-trust-auth-cli login [flags] <protected-url>
zero-trust-auth-cli renew [flags] <token-env-file>
```

Login flags:

- `-out FILE`: Write the shell token file somewhere else.
- `-resource URL`: Protected Cloudflare Access URL. This is an alternative to passing the URL as a positional argument.
- `-surge-dir DIR`: Also write `cf-zero-trust.js` and `cf-zero-trust.sgmodule` into `DIR`.
- `-callback-host HOST`: Use `127.0.0.1` or `localhost` for the callback. The default is `127.0.0.1`.
- `-timeout DURATION`: Browser authorization timeout. The default is `5m`.
- `-no-browser`: Print the authorization URL without trying to launch a browser.
- `-verbose`: Print the raw token endpoint response to stderr. This includes secrets.

Renew flags:

- `-out FILE`: Internal auto-renew path used by generated token files. For manual use, pass the token file as the positional argument.
- `-resource URL`: Protected Cloudflare Access URL used only if endpoint discovery is needed.
- `-timeout DURATION`: Token renewal timeout. The default is `30s`.
- `-verbose`: Print the raw token endpoint response to stderr. This includes secrets.

Your Cloudflare Access application must have Managed OAuth enabled and dynamic client registration configured for the callback host you use. For the default callback host, enable loopback clients for `127.0.0.1`.

## Surge integration (auto-inject `cf-access-token` header)

[Surge](https://nssurge.com/) integration is **opt-in**. Pass `-surge-dir DIR` to `login` and the CLI
writes two artifacts into `DIR` (typically the folder Surge loads modules
from). Without the flag, `login` only writes the normal per-host token file and
global loader.

```sh
zero-trust-auth-cli login -surge-dir /path/to/SurgeProfiles https://example.com
```

- `cf-zero-trust.js` — the shared http-request/http-response script. The bootstrap map
  (`refresh_token` / `client_id` / `token_endpoint` / `resource` per origin)
  is **inlined** between `// __CF_ZERO_TRUST_BOOTSTRAP_BEGIN__` /
  `_END__` markers as `const BOOTSTRAP = {…};`, so the script is
  self-contained and doesn't depend on `require()` or any companion file.
- `cf-zero-trust.sgmodule` — a ready-to-load Surge module with absolute
  `script-path`, a `hostname` list and a regex `pattern` built from every
  origin you've `login`'d. Re-running `login` for another origin merges it
  in by parsing the existing inlined BOOTSTRAP.

After `login` finishes, the CLI prints a Surge block with the exact next
steps: enable `Cloudflare Zero Trust Access Auto Auth` once under
**Surge → More → Modules**, then reload
Surge after every subsequent `login`. The script runs
`grant_type=refresh_token` against the OAuth `token_endpoint` from inside
Surge and injects `cf-access-token: <access_token>` on matching requests.
A `$notification.post` fires on first use or when a refresh fails.

See [`surge/README.md`](surge/README.md) for details.
