package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseBearerChallenge(t *testing.T) {
	header := `Bearer realm="OAuth", error="invalid_token", resource_metadata="https://example.com/.well-known/cloudflare-access-protected-resource/"`
	values := parseBearerChallenge(header)
	if got, want := values["resource_metadata"], "https://example.com/.well-known/cloudflare-access-protected-resource/"; got != want {
		t.Fatalf("resource_metadata = %q, want %q", got, want)
	}
	if got, want := values["error"], "invalid_token"; got != want {
		t.Fatalf("error = %q, want %q", got, want)
	}
}

func TestShellQuote(t *testing.T) {
	if got, want := shellQuote("can't"), `'can'\''t'`; got != want {
		t.Fatalf("shellQuote = %q, want %q", got, want)
	}
}

func TestParseShellEnv(t *testing.T) {
	env, err := parseShellEnv([]byte(`
# comment
export CF_ACCESS_TOKEN='oauth:access'
export CF_ACCESS_REFRESH_TOKEN='can'\''t'
CF_ACCESS_CLIENT_ID=client-1
`))
	if err != nil {
		t.Fatal(err)
	}
	if got, want := env["CF_ACCESS_TOKEN"], "oauth:access"; got != want {
		t.Fatalf("CF_ACCESS_TOKEN = %q, want %q", got, want)
	}
	if got, want := env["CF_ACCESS_REFRESH_TOKEN"], "can't"; got != want {
		t.Fatalf("CF_ACCESS_REFRESH_TOKEN = %q, want %q", got, want)
	}
	if got, want := env["CF_ACCESS_CLIENT_ID"], "client-1"; got != want {
		t.Fatalf("CF_ACCESS_CLIENT_ID = %q, want %q", got, want)
	}
}

func TestRenderShellEnv(t *testing.T) {
	issuedAt := time.Date(2026, 4, 25, 1, 2, 3, 0, time.UTC)
	result := &loginResult{
		Token: tokenResponse{
			AccessToken:  "oauth:access",
			RefreshToken: "oauth:refresh",
			TokenType:    "bearer",
			ExpiresIn:    900,
			Resource:     "https://example.com/",
		},
		ClientID:            "client-1",
		Resource:            "https://example.com/",
		AuthorizationServer: "https://team.cloudflareaccess.com",
		TokenEndpoint:       "https://team.cloudflareaccess.com/cdn-cgi/access/oauth/token",
		IssuedAt:            issuedAt,
	}

	env := renderShellEnv(result, issuedAt, "/tmp/token.env", "/tmp/config.json")
	for _, want := range []string{
		"export CF_ACCESS_TOKEN='oauth:access'",
		"export CF_ACCESS_REFRESH_TOKEN='oauth:refresh'",
		"export CF_ACCESS_TOKEN_EXPIRES_AT='2026-04-25T01:17:03Z'",
		"export CF_ACCESS_TOKEN_EXPIRES_AT_UNIX='1777079823'",
		"export CF_ACCESS_TOKEN_FILE='/tmp/token.env'",
		"export CF_ACCESS_CONFIG_FILE='/tmp/config.json'",
		"export CF_ACCESS_BEARER='Bearer oauth:access'",
		"export CF_ACCESS_AUTHORIZATION_HEADER='Authorization: Bearer oauth:access'",
		"zero-trust-auth-cli renew -config \"$CF_ACCESS_CONFIG_FILE\" -out \"$CF_ACCESS_TOKEN_FILE\"",
		"Suggested command: zero-trust-auth-cli login",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("rendered env missing %q:\n%s", want, env)
		}
	}
}

func TestGeneratedShellEnvAutoRenewsExpiredToken(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.env")
	configPath := filepath.Join(dir, "config.json")
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	mockCLI := filepath.Join(binDir, "zero-trust-auth-cli")
	mockScript := `#!/bin/sh
out=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -out)
      out="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [ -z "$out" ]; then
  exit 2
fi
cat > "$out" <<'EOF'
export CF_ACCESS_TOKEN='access-new'
export CF_ACCESS_AUTHORIZATION_HEADER='Authorization: Bearer access-new'
export CF_ACCESS_TOKEN_EXPIRES_AT_UNIX='4102444800'
EOF
`
	if err := os.WriteFile(mockCLI, []byte(mockScript), 0o755); err != nil {
		t.Fatal(err)
	}

	expired := &loginResult{
		Token: tokenResponse{
			AccessToken:  "access-old",
			RefreshToken: "refresh-old",
			TokenType:    "bearer",
			ExpiresIn:    1,
			Resource:     "https://example.com",
		},
		ClientID:            "client-1",
		Resource:            "https://example.com",
		AuthorizationServer: "https://team.cloudflareaccess.com",
		TokenEndpoint:       "https://team.cloudflareaccess.com/cdn-cgi/access/oauth/token",
		IssuedAt:            time.Unix(1, 0).UTC(),
	}
	if err := os.WriteFile(tokenPath, []byte(renderShellEnv(expired, time.Now().UTC(), tokenPath, configPath)), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", "-c", `. "$1" && [ "$CF_ACCESS_TOKEN" = "access-new" ] && [ "$CF_ACCESS_AUTHORIZATION_HEADER" = "Authorization: Bearer access-new" ]`, "sh", tokenPath)
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source expired env failed: %v\n%s", err, output)
	}
}

func TestGeneratedShellEnvPromptsLoginWhenRenewFails(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	dir := t.TempDir()
	tokenPath := filepath.Join(dir, "token.env")
	configPath := filepath.Join(dir, "config.json")
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	mockCLI := filepath.Join(binDir, "zero-trust-auth-cli")
	if err := os.WriteFile(mockCLI, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	expired := &loginResult{
		Token: tokenResponse{
			AccessToken:  "access-old",
			RefreshToken: "refresh-old",
			TokenType:    "bearer",
			ExpiresIn:    1,
			Resource:     "https://example.com",
		},
		ClientID:            "client-1",
		Resource:            "https://example.com",
		AuthorizationServer: "https://team.cloudflareaccess.com",
		TokenEndpoint:       "https://team.cloudflareaccess.com/cdn-cgi/access/oauth/token",
		IssuedAt:            time.Unix(1, 0).UTC(),
	}
	if err := os.WriteFile(tokenPath, []byte(renderShellEnv(expired, time.Now().UTC(), tokenPath, configPath)), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("sh", "-c", `. "$1"`, "sh", tokenPath)
	cmd.Env = append(os.Environ(), "PATH="+binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("source expired env with failed renew should not fail shell: %v\n%s", err, output)
	}
	text := string(output)
	if !strings.Contains(text, "The refresh token may be expired") {
		t.Fatalf("missing refresh-expired prompt:\n%s", text)
	}
	if !strings.Contains(text, "Suggested command: zero-trust-auth-cli login https://example.com") {
		t.Fatalf("missing login suggestion:\n%s", text)
	}
}

func TestRegisterClientRequestsRefreshTokenGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			GrantTypes []string `json:"grant_types"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if !contains(body.GrantTypes, "authorization_code") {
			t.Fatalf("grant_types = %v, missing authorization_code", body.GrantTypes)
		}
		if !contains(body.GrantTypes, "refresh_token") {
			t.Fatalf("grant_types = %v, missing refresh_token", body.GrantTypes)
		}
		_ = json.NewEncoder(w).Encode(registrationResponse{ClientID: "client-1"})
	}))
	defer server.Close()

	client, err := registerClient(context.Background(), server.Client(), server.URL, "http://127.0.0.1:1234/callback", "https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if client.ClientID != "client-1" {
		t.Fatalf("client id = %q, want client-1", client.ClientID)
	}
}

func TestRenewAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", r.Method)
		}
		if got, want := r.Header.Get("Content-Type"), "application/x-www-form-urlencoded"; got != want {
			t.Fatalf("content-type = %q, want %q", got, want)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertQuery(t, r.Form, "grant_type", "refresh_token")
		assertQuery(t, r.Form, "refresh_token", "refresh-old")
		assertQuery(t, r.Form, "client_id", "client-1")

		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:  "access-new",
			RefreshToken: "refresh-new",
			TokenType:    "bearer",
			ExpiresIn:    1800,
			Resource:     "https://example.com",
		})
	}))
	defer server.Close()

	var debug strings.Builder
	token, err := renewAccessToken(context.Background(), server.Client(), server.URL, "client-1", "refresh-old", &debug)
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access-new" {
		t.Fatalf("access token = %q, want access-new", token.AccessToken)
	}
	if token.RefreshToken != "refresh-new" {
		t.Fatalf("refresh token = %q, want refresh-new", token.RefreshToken)
	}
	if !strings.Contains(debug.String(), `"refresh_token":"refresh-new"`) {
		t.Fatalf("debug output did not include raw token response:\n%s", debug.String())
	}
}

func TestRunRenewRewritesTokenFile(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		assertQuery(t, r.Form, "grant_type", "refresh_token")
		assertQuery(t, r.Form, "refresh_token", "refresh-old")
		assertQuery(t, r.Form, "client_id", "client-1")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			AccessToken: "access-new",
			TokenType:   "bearer",
			ExpiresIn:   900,
			Resource:    "https://example.com",
		})
	}))
	defer server.Close()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	tokenPath := filepath.Join(dir, "token.env")
	initial := renderShellEnv(&loginResult{
		Token: tokenResponse{
			AccessToken:  "access-old",
			RefreshToken: "refresh-old",
			TokenType:    "bearer",
			ExpiresIn:    60,
			Resource:     "https://example.com",
		},
		ClientID:            "client-1",
		Resource:            "https://example.com",
		AuthorizationServer: server.URL,
		TokenEndpoint:       server.URL,
		IssuedAt:            time.Now().UTC(),
	}, time.Now().UTC(), tokenPath, configPath)
	if err := os.WriteFile(tokenPath, []byte(initial), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(configPath, &config{
		Resource:            "https://example.com",
		TokenFile:           tokenPath,
		AuthorizationServer: server.URL,
	}); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr strings.Builder
	if err := runRenew([]string{"-config", configPath}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}

	env, err := loadShellEnvFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := env["CF_ACCESS_TOKEN"], "access-new"; got != want {
		t.Fatalf("CF_ACCESS_TOKEN = %q, want %q", got, want)
	}
	if got, want := env["CF_ACCESS_REFRESH_TOKEN"], "refresh-old"; got != want {
		t.Fatalf("CF_ACCESS_REFRESH_TOKEN = %q, want preserved %q", got, want)
	}
	if got, want := env["CF_ACCESS_AUTHORIZATION_HEADER"], "Authorization: Bearer access-new"; got != want {
		t.Fatalf("CF_ACCESS_AUTHORIZATION_HEADER = %q, want %q", got, want)
	}
}

func TestDiscoverFromWWWAuthenticate(t *testing.T) {
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/protected":
			w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/cloudflare-access-protected-resource/"`, base))
			w.WriteHeader(http.StatusUnauthorized)
		case "/.well-known/cloudflare-access-protected-resource/":
			_ = json.NewEncoder(w).Encode(resourceMetadata{
				Resource:             base,
				Protected:            true,
				AuthorizationServers: []string{base},
			})
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(oauthMetadata{
				AuthorizationEndpoint:             base + "/authorize",
				TokenEndpoint:                     base + "/token",
				RegistrationEndpoint:              base + "/register",
				GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
				TokenEndpointAuthMethodsSupported: []string{"none"},
				CodeChallengeMethodsSupported:     []string{"S256"},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	base = server.URL

	resourceURL, err := url.Parse(base + "/protected")
	if err != nil {
		t.Fatal(err)
	}
	discovered, err := discover(context.Background(), server.Client(), resourceURL)
	if err != nil {
		t.Fatal(err)
	}
	if got := discovered.Resource; got != base {
		t.Fatalf("resource = %q, want %q", got, base)
	}
	if got := discovered.OAuth.AuthorizationEndpoint; got != base+"/authorize" {
		t.Fatalf("authorization endpoint = %q", got)
	}
}

func TestCallbackServerReceivesCode(t *testing.T) {
	server, err := startCallbackServer("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownServer(server.server)

	resp, err := http.Get(server.RedirectURI + "?code=code-1&state=state-1")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	result, err := waitForCallback(ctx, server, "state-1")
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != "code-1" {
		t.Fatalf("code = %q, want code-1", result.Code)
	}
}

func TestManualCallbackURLReceivesCode(t *testing.T) {
	server, err := startCallbackServer("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	defer shutdownServer(server.server)

	input := strings.NewReader(server.RedirectURI + "?code=manual-code&state=manual-state\n")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	result, err := waitForCallbackOrManualURL(ctx, server, input, "manual-state", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if result.Code != "manual-code" {
		t.Fatalf("code = %q, want manual-code", result.Code)
	}
}

func TestParseManualCallbackURLRejectsNonLoopback(t *testing.T) {
	_, err := parseManualCallbackURL("https://example.com/callback?code=bad&state=s", "http://127.0.0.1:1234/callback")
	if err == nil {
		t.Fatal("expected non-loopback callback URL to be rejected")
	}
}

func TestAuthorizationURL(t *testing.T) {
	got, err := authorizationURL("https://team.cloudflareaccess.com/cdn-cgi/access/oauth/authorization", "client", "http://127.0.0.1:1234/callback", "https://example.com", "state", "challenge")
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	query := parsed.Query()
	assertQuery(t, query, "client_id", "client")
	assertQuery(t, query, "redirect_uri", "http://127.0.0.1:1234/callback")
	assertQuery(t, query, "response_type", "code")
	assertQuery(t, query, "code_challenge_method", "S256")
	assertQuery(t, query, "resource", "https://example.com")
}

func assertQuery(t *testing.T, query url.Values, key, want string) {
	t.Helper()
	if got := query.Get(key); got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}
