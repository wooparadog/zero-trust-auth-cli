# zero-trust-auth-cli

`zero-trust-auth-cli` logs in to a Cloudflare Access protected resource through Cloudflare Zero Trust Managed OAuth and writes the result as a sourceable shell file.

The command:

1. Discovers the protected resource metadata.
2. Reads Cloudflare's hosted OAuth authorization server metadata.
3. Starts a local loopback callback server on a random port.
4. Dynamically registers a public OAuth client for that callback.
5. Prints the authorization URL and opens the browser when appropriate.
6. Receives the callback through the local server, or accepts the pasted localhost redirect URL on stdin.
7. Exchanges the callback code for an access token.
8. Writes shell exports to a private token file.

## Install

```sh
go install github.com/wooparadog/zero-trust-auth-cli@latest
```

From this checkout:

```sh
go build .
```

## Usage

```sh
zero-trust-auth-cli login https://example.com
. "$(zero-trust-auth-cli config-path)/token.env"

curl -H "$CF_ACCESS_AUTHORIZATION_HEADER" https://example.com
```

When running from a remote SSH session, copy the printed authorization URL into your local browser. After Cloudflare redirects to the localhost callback URL, the browser may fail to connect because the callback server is on the remote host. Copy that final `http://127.0.0.1:.../callback?...` URL from the browser address bar, paste it into the waiting CLI, and press Enter. The local callback server remains active at the same time, so normal non-SSH browser callbacks still work.

By default, config and token files are stored below Go's `os.UserConfigDir()`:

- Linux: `$XDG_CONFIG_HOME/zero-trust-auth-cli` or `$HOME/.config/zero-trust-auth-cli`
- macOS: `$HOME/Library/Application Support/zero-trust-auth-cli`

The token file is written with mode `0600` and contains exports such as:

```sh
export CF_ACCESS_TOKEN='oauth:...'
export CF_ACCESS_REFRESH_TOKEN='oauth:...'
export CF_ACCESS_BEARER='Bearer oauth:...'
export CF_ACCESS_AUTHORIZATION_HEADER='Authorization: Bearer oauth:...'
```

## Flags

```sh
zero-trust-auth-cli login [flags] <protected-url>
```

- `-out FILE`: Write the shell token file somewhere else.
- `-config FILE`: Use a different config file.
- `-callback-host HOST`: Use `127.0.0.1` or `localhost` for the callback. The default is `127.0.0.1`.
- `-timeout DURATION`: Browser authorization timeout. The default is `5m`.
- `-no-browser`: Print the authorization URL without trying to launch a browser.

Your Cloudflare Access application must have Managed OAuth enabled and dynamic client registration configured for the callback host you use. For the default callback host, enable loopback clients for `127.0.0.1`.
