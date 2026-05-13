package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

	env := renderShellEnv(result, issuedAt)
	for _, want := range []string{
		"export CF_ACCESS_TOKEN='oauth:access'",
		"export CF_ACCESS_REFRESH_TOKEN='oauth:refresh'",
		"export CF_ACCESS_TOKEN_EXPIRES_AT='2026-04-25T01:17:03Z'",
		"export CF_ACCESS_BEARER='Bearer oauth:access'",
		"export CF_ACCESS_AUTHORIZATION_HEADER='Authorization: Bearer oauth:access'",
	} {
		if !strings.Contains(env, want) {
			t.Fatalf("rendered env missing %q:\n%s", want, env)
		}
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
				GrantTypesSupported:               []string{"authorization_code"},
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
