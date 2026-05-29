package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed surge/cf-zero-trust.template.js
var embeddedSurgeScriptTemplate []byte

const appName = "zero-trust-auth-cli"

var version = "dev"

type config struct {
	Resource            string `json:"resource,omitempty"`
	TokenFile           string `json:"token_file,omitempty"`
	AuthorizationServer string `json:"authorization_server,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type appPaths struct {
	ConfigDir    string
	ConfigFile   string
	TokenFile    string
	TokensDir    string
	GlobalLoader string
}

type resourceMetadata struct {
	Resource                          string   `json:"resource"`
	Protected                         bool     `json:"protected"`
	TeamDomain                        string   `json:"team_domain"`
	AuthorizationServers              []string `json:"authorization_servers"`
	AuthenticationMethod              string   `json:"authentication_method"`
	AuthenticationMethodDescription   string   `json:"authentication_method_description"`
	AuthenticationMethodDocumentation string   `json:"authentication_method_documentation"`
}

type oauthMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope"`
	Resource     string `json:"resource"`
}

type loginResult struct {
	Token               tokenResponse
	ClientID            string
	Resource            string
	AuthorizationServer string
	TokenEndpoint       string
	IssuedAt            time.Time
}

type callbackServer struct {
	RedirectURI string
	results     <-chan callbackResult
	server      *http.Server
}

type callbackResult struct {
	Code             string
	State            string
	Error            string
	ErrorDescription string
}

type manualCallbackInput struct {
	Result callbackResult
	Err    error
}

func main() {
	if err := run(os.Args, os.Stdin, os.Stdout, os.Stderr); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) < 2 {
		printUsage(stdout)
		return nil
	}

	switch args[1] {
	case "login":
		return runLogin(args[2:], stdin, stdout, stderr)
	case "renew":
		return runRenew(args[2:], stdout, stderr)
	case "config-path":
		return runConfigPath(stdout)
	case "version":
		fmt.Fprintf(stdout, "%s %s\n", appName, version)
		return nil
	case "help", "-h", "--help":
		printUsage(stdout)
		return nil
	default:
		printUsage(stderr)
		return fmt.Errorf("unknown command %q", args[1])
	}
}

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `%[1]s gets OAuth tokens for Cloudflare Zero Trust Access.

Usage:
  %[1]s login [flags] <protected-url>
  %[1]s renew [flags]
  %[1]s config-path
  %[1]s version

Login flags:
  -resource URL          Protected Cloudflare Access URL. Overrides config.
  -out FILE              Sourceable shell output file. Defaults to the config dir.
  -config FILE           Config file path. Defaults to the config dir.
  -surge-dir DIR         If set, also write cf-zero-trust.js and cf-zero-trust.sgmodule
                         into DIR (typically the folder Surge loads modules from).
                         Omit to skip Surge artifact generation.
  -callback-host HOST    Loopback callback host: 127.0.0.1 or localhost. Defaults to 127.0.0.1.
  -timeout DURATION      Time to wait for browser authorization. Defaults to 5m.
  -no-browser            Print the authorization URL without trying to open a browser.
  -verbose               Print raw token endpoint responses to stderr. Contains secrets.

Renew flags:
  -out FILE              Sourceable shell token file to renew. Defaults to config.
  -config FILE           Config file path. Defaults to the config dir.
  -resource URL          Protected Cloudflare Access URL for endpoint discovery fallback.
  -timeout DURATION      Time to wait for token renewal. Defaults to 30s.
  -verbose               Print raw token endpoint responses to stderr. Contains secrets.

Example:
  %[1]s login https://example.com
  %[1]s login https://other.internal.example.com
  # Add once to shell startup:
  . "$(%[1]s config-path)/tokens.env"
  # Renew the last-used domain's token:
  %[1]s renew
  # Renew a specific domain's token:
  %[1]s renew -out "$(%[1]s config-path)/tokens/example.com.env"

Remote SSH:
  Open the printed authorization URL locally. If the browser cannot reach
  the localhost callback, paste the final localhost redirect URL into the CLI.

`, appName)
}

func runConfigPath(stdout io.Writer) error {
	paths, err := defaultPaths()
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, paths.ConfigDir)
	return nil
}

func runLogin(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	paths, err := defaultPaths()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	resourceFlag := fs.String("resource", "", "protected Cloudflare Access URL")
	outFlag := fs.String("out", "", "sourceable shell output file")
	configFlag := fs.String("config", paths.ConfigFile, "config file path")
	surgeDirFlag := fs.String("surge-dir", "", "if set, also write cf-zero-trust.js and cf-zero-trust.sgmodule into this directory (e.g. /path/to/SurgeProfiles). Omit to skip Surge artifact generation.")
	callbackHost := fs.String("callback-host", "127.0.0.1", "loopback callback host")
	timeout := fs.Duration("timeout", 5*time.Minute, "time to wait for browser authorization")
	noBrowser := fs.Bool("no-browser", false, "print auth URL without opening browser")
	verbose := fs.Bool("verbose", false, "print raw token endpoint responses to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 {
		return errors.New("login accepts at most one protected URL")
	}

	configPath, err := expandPath(*configFlag)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	resource := strings.TrimSpace(*resourceFlag)
	if fs.NArg() == 1 {
		resource = strings.TrimSpace(fs.Arg(0))
	}
	if resource == "" {
		resource = strings.TrimSpace(cfg.Resource)
	}
	if resource == "" {
		return errors.New("missing protected URL; pass one as an argument or with -resource")
	}

	resourceURL, err := normalizeResourceURL(resource)
	if err != nil {
		return err
	}

	outputPath := strings.TrimSpace(*outFlag)
	if outputPath == "" {
		outputPath = filepath.Join(paths.TokensDir, sanitizeHostname(resourceURL.Host)+".env")
	}
	outputPath, err = expandPath(outputPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	httpClient := &http.Client{Timeout: 30 * time.Second}
	result, err := login(ctx, httpClient, resourceURL, *callbackHost, !*noBrowser, stdin, stderr, *verbose)
	if err != nil {
		return err
	}

	shellFile := renderShellEnv(result, time.Now().UTC(), outputPath, configPath)
	if err := writePrivateFile(outputPath, []byte(shellFile)); err != nil {
		return err
	}

	loaderFile := renderGlobalLoader(paths.TokensDir)
	if err := writePrivateFile(paths.GlobalLoader, []byte(loaderFile)); err != nil {
		return err
	}

	scriptPath, modulePath, err := writeSurgeArtifacts(*surgeDirFlag, result)
	if err != nil {
		return err
	}

	cfg.Resource = result.Resource
	cfg.TokenFile = outputPath
	cfg.AuthorizationServer = result.AuthorizationServer
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Wrote token file: %s\n", outputPath)
	fmt.Fprintf(stdout, "Global loader:   %s\n", paths.GlobalLoader)
	fmt.Fprintf(stdout, "Add to shell startup: . %s\n", shellQuote(paths.GlobalLoader))
	printSurgeBlock(stdout, scriptPath, modulePath)
	return nil
}

func runRenew(args []string, stdout, stderr io.Writer) error {
	paths, err := defaultPaths()
	if err != nil {
		return err
	}

	fs := flag.NewFlagSet("renew", flag.ContinueOnError)
	fs.SetOutput(stderr)
	outFlag := fs.String("out", "", "sourceable shell token file to renew")
	configFlag := fs.String("config", paths.ConfigFile, "config file path")
	resourceFlag := fs.String("resource", "", "protected Cloudflare Access URL for endpoint discovery fallback")
	timeout := fs.Duration("timeout", 30*time.Second, "time to wait for token renewal")
	verbose := fs.Bool("verbose", false, "print raw token endpoint responses to stderr")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("renew does not accept positional arguments")
	}

	configPath, err := expandPath(*configFlag)
	if err != nil {
		return err
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	tokenPath := strings.TrimSpace(*outFlag)
	if tokenPath == "" {
		tokenPath = strings.TrimSpace(cfg.TokenFile)
	}
	if tokenPath == "" {
		tokenPath = paths.TokenFile
	}
	tokenPath, err = expandPath(tokenPath)
	if err != nil {
		return err
	}

	env, err := loadShellEnvFile(tokenPath)
	if err != nil {
		return err
	}

	refreshToken := strings.TrimSpace(env["CF_ACCESS_REFRESH_TOKEN"])
	if refreshToken == "" {
		return fmt.Errorf("%s does not include CF_ACCESS_REFRESH_TOKEN; run login again", tokenPath)
	}
	clientID := strings.TrimSpace(env["CF_ACCESS_CLIENT_ID"])
	if clientID == "" {
		return fmt.Errorf("%s does not include CF_ACCESS_CLIENT_ID; run login again", tokenPath)
	}

	resource := firstNonEmpty(*resourceFlag, env["CF_ACCESS_RESOURCE"], cfg.Resource)
	authServer := firstNonEmpty(env["CF_ACCESS_AUTHORIZATION_SERVER"], cfg.AuthorizationServer)
	tokenEndpoint := strings.TrimSpace(env["CF_ACCESS_TOKEN_ENDPOINT"])

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	httpClient := &http.Client{Timeout: 30 * time.Second}
	if tokenEndpoint == "" {
		tokenEndpoint, authServer, err = discoverTokenEndpointForRenew(ctx, httpClient, resource, authServer)
		if err != nil {
			return err
		}
	}

	fmt.Fprintln(stderr, "Renewing access token with saved refresh token")
	token, err := renewAccessToken(ctx, httpClient, tokenEndpoint, clientID, refreshToken, verboseWriter(stderr, *verbose))
	if err != nil {
		return err
	}
	if token.AccessToken == "" {
		return errors.New("token endpoint response did not include access_token")
	}
	if token.RefreshToken == "" {
		token.RefreshToken = refreshToken
	}
	if token.TokenType == "" {
		token.TokenType = firstNonEmpty(env["CF_ACCESS_TOKEN_TYPE"], "bearer")
	}
	if token.Resource == "" {
		token.Resource = resource
	}

	now := time.Now().UTC()
	result := &loginResult{
		Token:               token,
		ClientID:            clientID,
		Resource:            token.Resource,
		AuthorizationServer: authServer,
		TokenEndpoint:       tokenEndpoint,
		IssuedAt:            now,
	}

	shellFile := renderShellEnv(result, now, tokenPath, configPath)
	if err := writePrivateFile(tokenPath, []byte(shellFile)); err != nil {
		return err
	}

	cfg.Resource = firstNonEmpty(result.Resource, cfg.Resource)
	cfg.TokenFile = tokenPath
	cfg.AuthorizationServer = firstNonEmpty(result.AuthorizationServer, cfg.AuthorizationServer)
	cfg.UpdatedAt = now.Format(time.RFC3339)
	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Renewed sourceable token file: %s\n", tokenPath)
	fmt.Fprintf(stdout, "Reload it with: . %s\n", shellQuote(tokenPath))
	return nil
}

// writeSurgeArtifacts merges the result into the BOOTSTRAP map inlined in
// cf-zero-trust.js, regenerates the script and sgmodule, and returns the
// absolute paths. If surgeDir is empty, this is a no-op.
func writeSurgeArtifacts(surgeDir string, result *loginResult) (scriptPath, modulePath string, err error) {
	surgeDir = strings.TrimSpace(surgeDir)
	if surgeDir == "" {
		return "", "", nil
	}
	surgeDir, err = expandPath(surgeDir)
	if err != nil {
		return "", "", err
	}
	scriptPath = filepath.Join(surgeDir, "cf-zero-trust.js")
	entries := readBootstrapFromScript(scriptPath)
	entries[surgeBootstrapKey(result.Resource)] = surgeBootstrapEntry{
		Resource:      result.Resource,
		RefreshToken:  result.Token.RefreshToken,
		ClientID:      result.ClientID,
		TokenEndpoint: result.TokenEndpoint,
	}
	scriptBody, err := renderSurgeScript(entries)
	if err != nil {
		return "", "", fmt.Errorf("render surge script: %w", err)
	}
	if err := writePrivateFile(scriptPath, scriptBody); err != nil {
		return "", "", fmt.Errorf("write surge script %s: %w", scriptPath, err)
	}
	modulePath = filepath.Join(surgeDir, "cf-zero-trust.sgmodule")
	moduleBody := renderSurgeModule(entries, scriptPath)
	if err := writePrivateFile(modulePath, []byte(moduleBody)); err != nil {
		return "", "", fmt.Errorf("write surge module %s: %w", modulePath, err)
	}
	return scriptPath, modulePath, nil
}

func printSurgeBlock(stdout io.Writer, scriptPath, modulePath string) {
	if scriptPath == "" {
		return
	}
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "────────────────────────────── Surge ──────────────────────────────")
	fmt.Fprintf(stdout, "  script:    %s\n", scriptPath)
	fmt.Fprintf(stdout, "  sgmodule:  %s\n", modulePath)
	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "  Next steps:")
	fmt.Fprintln(stdout, "    1. First time only — Surge → More → Modules → enable `Cloudflare Zero Trust Access Auto Auth`.")
	fmt.Fprintln(stdout, "    2. After every login — reload Surge so the updated BOOTSTRAP")
	fmt.Fprintln(stdout, "       takes effect (Surge menu bar → Reload, or restart Surge).")
	fmt.Fprintln(stdout, "────────────────────────────────────────────────────────────────────")
}

type surgeBootstrapEntry struct {
	Resource      string `json:"resource"`
	RefreshToken  string `json:"refresh_token"`
	ClientID      string `json:"client_id"`
	TokenEndpoint string `json:"token_endpoint"`
}

const (
	bootstrapBeginMarker = "// __CF_ZERO_TRUST_BOOTSTRAP_BEGIN__"
	bootstrapEndMarker   = "// __CF_ZERO_TRUST_BOOTSTRAP_END__"
)

func readBootstrapFromScript(path string) map[string]surgeBootstrapEntry {
	out := map[string]surgeBootstrapEntry{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	s := string(data)
	i := strings.Index(s, bootstrapBeginMarker)
	j := strings.Index(s, bootstrapEndMarker)
	if i < 0 || j <= i {
		return out
	}
	block := s[i+len(bootstrapBeginMarker) : j]
	a := strings.Index(block, "{")
	b := strings.LastIndex(block, "}")
	if a < 0 || b <= a {
		return out
	}
	_ = json.Unmarshal([]byte(block[a:b+1]), &out)
	if out == nil {
		out = map[string]surgeBootstrapEntry{}
	}
	return out
}

func surgeBootstrapKey(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return strings.TrimRight(strings.TrimSpace(raw), "/")
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

func renderSurgeScript(entries map[string]surgeBootstrapEntry) ([]byte, error) {
	if entries == nil {
		entries = map[string]surgeBootstrapEntry{}
	}
	body, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return nil, err
	}
	rendered := strings.Replace(string(embeddedSurgeScriptTemplate), "__CF_ZERO_TRUST_BOOTSTRAP__", string(body), 1)
	return []byte(rendered), nil
}

func renderSurgeModule(entries map[string]surgeBootstrapEntry, scriptPath string) string {
	var hosts []string
	for origin := range entries {
		u, err := url.Parse(origin)
		if err != nil || u.Hostname() == "" {
			continue
		}
		hosts = append(hosts, u.Hostname())
	}
	sort.Strings(hosts)
	hosts = dedupe(hosts)

	hostnameList := "example.com"
	var pattern string
	if len(hosts) > 0 {
		hostnameList = strings.Join(hosts, ", ")
		escaped := make([]string, len(hosts))
		for i, h := range hosts {
			escaped[i] = regexp.QuoteMeta(h)
		}
		pattern = "^https?:\\/\\/(" + strings.Join(escaped, "|") + ")(\\/.*)?$"
	} else {
		pattern = "^https?:\\/\\/example\\.com(\\/.*)?$"
	}

	return fmt.Sprintf(`#!name=Cloudflare Zero Trust Access Auto Auth
#!desc=Auto-generated by zero-trust-auth-cli. Injects cf-access-token header for Cloudflare Access protected hosts, and invalidates the cached token when upstream replies 401. Re-run `+"`zero-trust-auth-cli login <url>`"+` to update.

[MITM]
hostname = %%APPEND%% %s

[Script]
cf-zero-trust-auth = type=http-request,pattern=%s,requires-body=0,max-size=0,timeout=5,script-path=%s
cf-zero-trust-invalidate = type=http-response,pattern=%s,requires-body=0,max-size=0,timeout=5,script-path=%s
`, hostnameList, pattern, scriptPath, pattern, scriptPath)
}

func dedupe(in []string) []string {
	if len(in) <= 1 {
		return in
	}
	out := in[:1]
	for _, v := range in[1:] {
		if v != out[len(out)-1] {
			out = append(out, v)
		}
	}
	return out
}

func login(ctx context.Context, client *http.Client, resourceURL *url.URL, callbackHost string, openBrowser bool, stdin io.Reader, logw io.Writer, verbose bool) (*loginResult, error) {
	if !isLoopbackHost(callbackHost) {
		return nil, fmt.Errorf("callback host must be localhost or a loopback address, got %q", callbackHost)
	}

	fmt.Fprintf(logw, "Discovering Cloudflare Access metadata for %s\n", resourceURL.String())
	discovered, err := discover(ctx, client, resourceURL)
	if err != nil {
		return nil, err
	}

	cb, err := startCallbackServer(callbackHost)
	if err != nil {
		return nil, err
	}
	defer shutdownServer(cb.server)

	fmt.Fprintf(logw, "Registering OAuth client with callback %s\n", cb.RedirectURI)
	clientReg, err := registerClient(ctx, client, discovered.OAuth.RegistrationEndpoint, cb.RedirectURI, discovered.Resource)
	if err != nil {
		return nil, err
	}

	codeVerifier, codeChallenge, err := newPKCE()
	if err != nil {
		return nil, err
	}
	state, err := randomBase64URL(32)
	if err != nil {
		return nil, err
	}

	authURL, err := authorizationURL(discovered.OAuth.AuthorizationEndpoint, clientReg.ClientID, cb.RedirectURI, discovered.Resource, state, codeChallenge)
	if err != nil {
		return nil, err
	}

	if openBrowser && shouldOpenBrowser() {
		if err := openAuthURL(authURL); err != nil {
			fmt.Fprintf(logw, "Could not open browser automatically: %v\n", err)
		}
	} else if openBrowser {
		fmt.Fprintln(logw, "SSH session detected; skipping automatic browser open.")
	}
	fmt.Fprintf(logw, "\nAuthorization URL:\n%s\n\n", authURL)
	fmt.Fprintf(logw, "Local callback URL: %s\n", cb.RedirectURI)
	fmt.Fprintln(logw, "If the browser cannot reach that callback, paste the final localhost redirect URL here and press Enter.")

	cbResult, err := waitForCallbackOrManualURL(ctx, cb, stdin, state, logw)
	if err != nil {
		return nil, err
	}

	fmt.Fprintln(logw, "Authorization code received; exchanging it for a token")
	token, err := exchangeCode(ctx, client, discovered.OAuth.TokenEndpoint, clientReg.ClientID, cb.RedirectURI, cbResult.Code, codeVerifier, verboseWriter(logw, verbose))
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("token endpoint response did not include access_token")
	}
	if token.RefreshToken == "" {
		return nil, errors.New("token endpoint response did not include refresh_token; ensure Cloudflare Managed OAuth has a nonzero grant session duration and supports refresh_token grants")
	}
	if token.Resource == "" {
		token.Resource = discovered.Resource
	}
	if token.TokenType == "" {
		token.TokenType = "bearer"
	}

	return &loginResult{
		Token:               token,
		ClientID:            clientReg.ClientID,
		Resource:            discovered.Resource,
		AuthorizationServer: discovered.AuthorizationServer,
		TokenEndpoint:       discovered.OAuth.TokenEndpoint,
		IssuedAt:            time.Now().UTC(),
	}, nil
}

type discoveryResult struct {
	Resource            string
	ResourceMetadataURL string
	AuthorizationServer string
	OAuth               oauthMetadata
}

func discover(ctx context.Context, client *http.Client, resourceURL *url.URL) (*discoveryResult, error) {
	metaURL, err := discoverResourceMetadataURL(ctx, client, resourceURL.String())
	if err != nil {
		fallbackURL, fallbackErr := wellKnownURL(resourceURL.String(), "/.well-known/cloudflare-access-protected-resource/")
		if fallbackErr != nil {
			return nil, err
		}
		metaURL = fallbackURL
	}

	resourceMeta, err := fetchResourceMetadata(ctx, client, metaURL)
	if err != nil {
		if directErr := err; metaURL != "" {
			oauthMeta, oauthErr := fetchOAuthMetadata(ctx, client, resourceURL.String())
			if oauthErr == nil {
				if err := validateOAuthMetadata(oauthMeta); err != nil {
					return nil, err
				}
				return &discoveryResult{
					Resource:            resourceOrigin(resourceURL),
					ResourceMetadataURL: "",
					AuthorizationServer: strings.TrimRight(resourceOrigin(resourceURL), "/"),
					OAuth:               *oauthMeta,
				}, nil
			}
			return nil, fmt.Errorf("fetch resource metadata %s: %w", metaURL, directErr)
		}
		return nil, err
	}
	if len(resourceMeta.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("resource metadata %s did not include authorization_servers", metaURL)
	}

	authServer := resourceMeta.AuthorizationServers[0]
	oauthMeta, err := fetchOAuthMetadata(ctx, client, authServer)
	if err != nil {
		return nil, err
	}
	if err := validateOAuthMetadata(oauthMeta); err != nil {
		return nil, err
	}

	resource := strings.TrimSpace(resourceMeta.Resource)
	if resource == "" {
		resource = resourceOrigin(resourceURL)
	}
	return &discoveryResult{
		Resource:            resource,
		ResourceMetadataURL: metaURL,
		AuthorizationServer: strings.TrimRight(authServer, "/"),
		OAuth:               *oauthMeta,
	}, nil
}

func discoverResourceMetadataURL(ctx context.Context, client *http.Client, target string) (string, error) {
	noRedirect := *client
	noRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent())

	resp, err := noRedirect.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	for _, header := range resp.Header.Values("WWW-Authenticate") {
		if metadata := parseBearerChallenge(header)["resource_metadata"]; metadata != "" {
			return metadata, nil
		}
	}

	var body struct {
		ResourceMetadata string `json:"resource_metadata"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err == nil && body.ResourceMetadata != "" {
		return body.ResourceMetadata, nil
	}

	return "", fmt.Errorf("response from %s did not include OAuth resource metadata", target)
}

func fetchResourceMetadata(ctx context.Context, client *http.Client, metadataURL string) (*resourceMetadata, error) {
	var metadata resourceMetadata
	if err := fetchJSON(ctx, client, metadataURL, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

func fetchOAuthMetadata(ctx context.Context, client *http.Client, authServer string) (*oauthMetadata, error) {
	metadataURL, err := wellKnownURL(authServer, "/.well-known/oauth-authorization-server")
	if err != nil {
		return nil, err
	}
	var metadata oauthMetadata
	if err := fetchJSON(ctx, client, metadataURL, &metadata); err != nil {
		return nil, fmt.Errorf("fetch OAuth authorization server metadata %s: %w", metadataURL, err)
	}
	return &metadata, nil
}

func validateOAuthMetadata(metadata *oauthMetadata) error {
	if metadata.AuthorizationEndpoint == "" {
		return errors.New("OAuth metadata did not include authorization_endpoint")
	}
	if metadata.TokenEndpoint == "" {
		return errors.New("OAuth metadata did not include token_endpoint")
	}
	if metadata.RegistrationEndpoint == "" {
		return errors.New("OAuth metadata did not include registration_endpoint; dynamic client registration may be disabled")
	}
	if len(metadata.GrantTypesSupported) > 0 && !contains(metadata.GrantTypesSupported, "authorization_code") {
		return errors.New("OAuth server does not advertise authorization_code grant support")
	}
	if len(metadata.GrantTypesSupported) > 0 && !contains(metadata.GrantTypesSupported, "refresh_token") {
		return errors.New("OAuth server does not advertise refresh_token grant support")
	}
	if len(metadata.CodeChallengeMethodsSupported) > 0 && !contains(metadata.CodeChallengeMethodsSupported, "S256") {
		return errors.New("OAuth server does not advertise S256 PKCE support")
	}
	if len(metadata.TokenEndpointAuthMethodsSupported) > 0 && !contains(metadata.TokenEndpointAuthMethodsSupported, "none") {
		return errors.New("OAuth server does not advertise public clients with token_endpoint_auth_method=none")
	}
	return nil
}

func registerClient(ctx context.Context, client *http.Client, endpoint, redirectURI, resource string) (*registrationResponse, error) {
	body := map[string]any{
		"redirect_uris":              []string{redirectURI},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"client_name":                appName,
		"resource":                   resource,
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", userAgent())

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("client registration failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var result registrationResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result); err != nil {
		return nil, err
	}
	if result.ClientID == "" {
		return nil, errors.New("client registration response did not include client_id")
	}
	return &result, nil
}

func exchangeCode(ctx context.Context, client *http.Client, endpoint, clientID, redirectURI, code, codeVerifier string, debugw io.Writer) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", clientID)
	form.Set("redirect_uri", redirectURI)
	form.Set("code_verifier", codeVerifier)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent())

	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, err
	}
	printRawTokenResponse(debugw, "authorization_code", resp.StatusCode, data)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return tokenResponse{}, fmt.Errorf("token exchange failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var token tokenResponse
	if err := json.Unmarshal(data, &token); err != nil {
		return tokenResponse{}, err
	}
	return token, nil
}

func renewAccessToken(ctx context.Context, client *http.Client, endpoint, clientID, refreshToken string, debugw io.Writer) (tokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", clientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return tokenResponse{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent())

	resp, err := client.Do(req)
	if err != nil {
		return tokenResponse{}, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tokenResponse{}, err
	}
	printRawTokenResponse(debugw, "refresh_token", resp.StatusCode, data)

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return tokenResponse{}, fmt.Errorf("token renewal failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var token tokenResponse
	if err := json.Unmarshal(data, &token); err != nil {
		return tokenResponse{}, err
	}
	return token, nil
}

func verboseWriter(w io.Writer, enabled bool) io.Writer {
	if !enabled {
		return nil
	}
	return w
}

func printRawTokenResponse(w io.Writer, grantType string, statusCode int, body []byte) {
	if w == nil {
		return
	}
	fmt.Fprintf(w, "\nRaw token endpoint response for grant_type=%s (HTTP %d):\n%s\n\n", grantType, statusCode, strings.TrimSpace(string(body)))
}

func discoverTokenEndpointForRenew(ctx context.Context, client *http.Client, resource, authServer string) (tokenEndpoint string, resolvedAuthServer string, err error) {
	if strings.TrimSpace(authServer) != "" {
		metadata, err := fetchOAuthMetadata(ctx, client, authServer)
		if err != nil {
			return "", "", err
		}
		if metadata.TokenEndpoint == "" {
			return "", "", errors.New("OAuth metadata did not include token_endpoint")
		}
		return metadata.TokenEndpoint, strings.TrimRight(authServer, "/"), nil
	}
	if strings.TrimSpace(resource) == "" {
		return "", "", errors.New("token file does not include CF_ACCESS_TOKEN_ENDPOINT and config has no authorization server or resource for discovery; run login again")
	}
	resourceURL, err := normalizeResourceURL(resource)
	if err != nil {
		return "", "", err
	}
	discovered, err := discover(ctx, client, resourceURL)
	if err != nil {
		return "", "", err
	}
	return discovered.OAuth.TokenEndpoint, discovered.AuthorizationServer, nil
}

func startCallbackServer(callbackHost string) (*callbackServer, error) {
	listener, err := net.Listen("tcp", net.JoinHostPort(callbackHost, "0"))
	if err != nil {
		return nil, fmt.Errorf("start local callback listener: %w", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		return nil, err
	}

	redirectURI := (&url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(callbackHost, port),
		Path:   "/callback",
	}).String()

	resultCh := make(chan callbackResult, 1)
	mux := http.NewServeMux()
	server := &http.Server{
		Handler: mux,
	}

	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		query := r.URL.Query()
		result := callbackResult{
			Code:             query.Get("code"),
			State:            query.Get("state"),
			Error:            query.Get("error"),
			ErrorDescription: query.Get("error_description"),
		}

		if result.Error != "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<!doctype html><title>Authorization failed</title><h1>Authorization failed</h1><p>%s</p>", html.EscapeString(result.ErrorDescription))
		} else if result.Code == "" {
			http.Error(w, "missing authorization code", http.StatusBadRequest)
			return
		} else {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, "<!doctype html><title>Authorized</title><h1>Authorized</h1><p>You can close this tab.</p>")
		}

		select {
		case resultCh <- result:
		default:
		}
		go shutdownServer(server)
	})

	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			select {
			case resultCh <- callbackResult{Error: "callback_server_error", ErrorDescription: err.Error()}:
			default:
			}
		}
	}()

	return &callbackServer{
		RedirectURI: redirectURI,
		results:     resultCh,
		server:      server,
	}, nil
}

func waitForCallback(ctx context.Context, server *callbackServer, expectedState string) (callbackResult, error) {
	select {
	case result := <-server.results:
		return validateCallbackResult(result, expectedState)
	case <-ctx.Done():
		return callbackResult{}, fmt.Errorf("waiting for authorization callback: %w", ctx.Err())
	}
}

func waitForCallbackOrManualURL(ctx context.Context, server *callbackServer, stdin io.Reader, expectedState string, logw io.Writer) (callbackResult, error) {
	manualInputs := readManualCallbackURLs(stdin, server.RedirectURI)

	for {
		select {
		case result := <-server.results:
			return validateCallbackResult(result, expectedState)
		case input, ok := <-manualInputs:
			if !ok {
				manualInputs = nil
				continue
			}
			if input.Err != nil {
				fmt.Fprintf(logw, "Could not use pasted callback URL: %v\n", input.Err)
				continue
			}
			result, err := validateCallbackResult(input.Result, expectedState)
			if err != nil {
				if input.Result.Error != "" {
					return callbackResult{}, err
				}
				fmt.Fprintf(logw, "Could not use pasted callback URL: %v\n", err)
				continue
			}
			go shutdownServer(server.server)
			return result, nil
		case <-ctx.Done():
			return callbackResult{}, fmt.Errorf("waiting for authorization callback: %w", ctx.Err())
		}
	}
}

func readManualCallbackURLs(stdin io.Reader, redirectURI string) <-chan manualCallbackInput {
	inputs := make(chan manualCallbackInput, 1)
	go func() {
		defer close(inputs)
		if stdin == nil {
			return
		}

		scanner := bufio.NewScanner(stdin)
		scanner.Buffer(make([]byte, 1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			result, err := parseManualCallbackURL(line, redirectURI)
			inputs <- manualCallbackInput{Result: result, Err: err}
		}
		if err := scanner.Err(); err != nil {
			inputs <- manualCallbackInput{Err: fmt.Errorf("read pasted callback URL: %w", err)}
		}
	}()
	return inputs
}

func parseManualCallbackURL(raw, redirectURI string) (callbackResult, error) {
	raw = strings.Trim(strings.TrimSpace(raw), `"'`)
	if raw == "" {
		return callbackResult{}, errors.New("empty callback URL")
	}

	var query url.Values
	if strings.Contains(raw, "://") {
		callbackURL, err := url.Parse(raw)
		if err != nil {
			return callbackResult{}, err
		}
		if callbackURL.Scheme == "" || callbackURL.Host == "" {
			return callbackResult{}, errors.New("callback URL must be absolute")
		}
		if !isLoopbackHost(callbackURL.Hostname()) {
			return callbackResult{}, fmt.Errorf("callback URL host must be localhost or loopback, got %q", callbackURL.Hostname())
		}
		expected, err := url.Parse(redirectURI)
		if err != nil {
			return callbackResult{}, err
		}
		if callbackURL.Path != expected.Path {
			return callbackResult{}, fmt.Errorf("callback URL path %q does not match expected path %q", callbackURL.Path, expected.Path)
		}
		query = callbackURL.Query()
	} else {
		raw = strings.TrimPrefix(raw, "?")
		parsed, err := url.ParseQuery(raw)
		if err != nil {
			return callbackResult{}, err
		}
		query = parsed
	}

	result := callbackResult{
		Code:             query.Get("code"),
		State:            query.Get("state"),
		Error:            query.Get("error"),
		ErrorDescription: query.Get("error_description"),
	}
	if result.Code == "" && result.Error == "" {
		return callbackResult{}, errors.New("callback URL did not include code or error")
	}
	return result, nil
}

func validateCallbackResult(result callbackResult, expectedState string) (callbackResult, error) {
	if result.Error != "" {
		if result.ErrorDescription != "" {
			return callbackResult{}, fmt.Errorf("authorization failed: %s: %s", result.Error, result.ErrorDescription)
		}
		return callbackResult{}, fmt.Errorf("authorization failed: %s", result.Error)
	}
	if result.State != expectedState {
		return callbackResult{}, errors.New("authorization callback state did not match")
	}
	return result, nil
}

func shutdownServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}

func authorizationURL(endpoint, clientID, redirectURI, resource, state, codeChallenge string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	query := u.Query()
	query.Set("client_id", clientID)
	query.Set("redirect_uri", redirectURI)
	query.Set("response_type", "code")
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	query.Set("state", state)
	if resource != "" {
		query.Set("resource", resource)
	}
	u.RawQuery = query.Encode()
	return u.String(), nil
}

func newPKCE() (verifier string, challenge string, err error) {
	for {
		verifier, err = randomBase64URL(32)
		if err != nil {
			return "", "", err
		}
		sum := sha256.Sum256([]byte(verifier))
		challenge = base64.RawURLEncoding.EncodeToString(sum[:])
		if challenge != "" && isAlphaNum(challenge[0]) {
			return verifier, challenge, nil
		}
	}
}

func randomBase64URL(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func fetchJSON(ctx context.Context, client *http.Client, target string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent())

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

func parseBearerChallenge(header string) map[string]string {
	result := map[string]string{}
	header = strings.TrimSpace(header)
	if len(header) < len("Bearer") || !strings.EqualFold(header[:len("Bearer")], "Bearer") {
		return result
	}
	rest := strings.TrimSpace(header[len("Bearer"):])
	if strings.HasPrefix(rest, ",") {
		rest = strings.TrimSpace(rest[1:])
	}

	for len(rest) > 0 {
		rest = strings.TrimLeft(rest, " ,")
		if rest == "" {
			break
		}

		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			break
		}
		key := strings.TrimSpace(rest[:eq])
		rest = strings.TrimSpace(rest[eq+1:])

		var value string
		if strings.HasPrefix(rest, "\"") {
			var b strings.Builder
			rest = rest[1:]
			escaped := false
			i := 0
			for ; i < len(rest); i++ {
				ch := rest[i]
				if escaped {
					b.WriteByte(ch)
					escaped = false
					continue
				}
				if ch == '\\' {
					escaped = true
					continue
				}
				if ch == '"' {
					i++
					break
				}
				b.WriteByte(ch)
			}
			value = b.String()
			rest = rest[i:]
		} else {
			end := strings.IndexByte(rest, ',')
			if end < 0 {
				value = strings.TrimSpace(rest)
				rest = ""
			} else {
				value = strings.TrimSpace(rest[:end])
				rest = rest[end+1:]
			}
		}
		if key != "" {
			result[strings.ToLower(key)] = value
		}

		if comma := strings.IndexByte(rest, ','); comma == 0 {
			rest = rest[1:]
		}
	}
	return result
}

func renderShellEnv(result *loginResult, generatedAt time.Time, tokenFile, configFile string) string {
	expiresAt := ""
	expiresAtUnix := ""
	if result.Token.ExpiresIn > 0 {
		expiresAtTime := result.IssuedAt.Add(time.Duration(result.Token.ExpiresIn) * time.Second)
		expiresAt = expiresAtTime.Format(time.RFC3339)
		expiresAtUnix = strconv.FormatInt(expiresAtTime.Unix(), 10)
	}

	// Derive a per-domain variable suffix, e.g. "_EXAMPLE_COM" from https://example.com
	domainSuffix := ""
	if u, err := url.Parse(result.Resource); err == nil && u.Host != "" {
		domainSuffix = "_" + hostnameToVarSuffix(u.Host)
	}

	values := [][2]string{
		{"CF_ACCESS_TOKEN", result.Token.AccessToken},
		{"CF_ACCESS_REFRESH_TOKEN", result.Token.RefreshToken},
		{"CF_ACCESS_TOKEN_TYPE", result.Token.TokenType},
		{"CF_ACCESS_TOKEN_EXPIRES_IN", strconv.FormatInt(result.Token.ExpiresIn, 10)},
		{"CF_ACCESS_TOKEN_EXPIRES_AT", expiresAt},
		{"CF_ACCESS_TOKEN_EXPIRES_AT_UNIX", expiresAtUnix},
		{"CF_ACCESS_RESOURCE", result.Token.Resource},
		{"CF_ACCESS_CLIENT_ID", result.ClientID},
		{"CF_ACCESS_AUTHORIZATION_SERVER", result.AuthorizationServer},
		{"CF_ACCESS_TOKEN_ENDPOINT", result.TokenEndpoint},
		{"CF_ACCESS_TOKEN_FILE", tokenFile},
		{"CF_ACCESS_CONFIG_FILE", configFile},
	}

	writeExport := func(b *strings.Builder, name, value string) {
		b.WriteString("export ")
		b.WriteString(name)
		b.WriteByte('=')
		b.WriteString(shellQuote(value))
		b.WriteByte('\n')
		if domainSuffix != "" {
			b.WriteString("export ")
			b.WriteString(name)
			b.WriteString(domainSuffix)
			b.WriteByte('=')
			b.WriteString(shellQuote(value))
			b.WriteByte('\n')
		}
	}

	var b strings.Builder
	b.WriteString("# Generated by zero-trust-auth-cli at ")
	b.WriteString(generatedAt.Format(time.RFC3339))
	b.WriteString("\n")
	b.WriteString("# Use as: source this-file\n")
	for _, item := range values {
		if item[1] == "" {
			continue
		}
		writeExport(&b, item[0], item[1])
	}
	if result.Token.AccessToken != "" {
		writeExport(&b, "CF_ACCESS_BEARER", "Bearer "+result.Token.AccessToken)
		writeExport(&b, "CF_ACCESS_AUTHORIZATION_HEADER", "Authorization: Bearer "+result.Token.AccessToken)
	}
	writeAutoRenewShell(&b)
	return b.String()
}

func writeAutoRenewShell(b *strings.Builder) {
	b.WriteString(`

cf_access_token_expired() {
  [ -n "${CF_ACCESS_TOKEN_EXPIRES_AT_UNIX:-}" ] && [ "$(date +%s)" -ge "${CF_ACCESS_TOKEN_EXPIRES_AT_UNIX:-0}" ]
}

if [ -z "${CF_ACCESS_TOKEN_AUTO_RENEWING:-}" ] && cf_access_token_expired; then
  if command -v zero-trust-auth-cli >/dev/null 2>&1; then
    CF_ACCESS_TOKEN_AUTO_RENEWING=1
    if zero-trust-auth-cli renew -config "$CF_ACCESS_CONFIG_FILE" -out "$CF_ACCESS_TOKEN_FILE" >/dev/null; then
      if [ -f "$CF_ACCESS_TOKEN_FILE" ]; then
        . "$CF_ACCESS_TOKEN_FILE"
      fi
    else
      printf '%s\n' 'zero-trust-auth-cli could not renew the Cloudflare Access token.' >&2
      printf '%s\n' 'The refresh token may be expired. Please run login again; no login command was executed automatically.' >&2
      if [ -n "${CF_ACCESS_RESOURCE:-}" ]; then
        printf '%s\n' "Suggested command: zero-trust-auth-cli login ${CF_ACCESS_RESOURCE}" >&2
      else
        printf '%s\n' 'Suggested command: zero-trust-auth-cli login <protected-url>' >&2
      fi
    fi
    unset CF_ACCESS_TOKEN_AUTO_RENEWING
  else
    printf '%s\n' 'Cloudflare Access token is expired, but zero-trust-auth-cli was not found in PATH.' >&2
    printf '%s\n' 'Install zero-trust-auth-cli or run zero-trust-auth-cli renew manually.' >&2
  fi
fi
`)
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func loadShellEnvFile(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env, err := parseShellEnv(data)
	if err != nil {
		return nil, fmt.Errorf("read shell env %s: %w", path, err)
	}
	return env, nil
}

func parseShellEnv(data []byte) (map[string]string, error) {
	env := map[string]string{}
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		if !isShellIdentifier(key) {
			return nil, fmt.Errorf("line %d has invalid shell variable name %q", lineNumber, key)
		}
		value, err := parseShellValue(line[eq+1:])
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber, err)
		}
		env[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return env, nil
}

func parseShellValue(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	var b strings.Builder
	for i := 0; i < len(raw); {
		switch raw[i] {
		case '\'':
			i++
			for i < len(raw) && raw[i] != '\'' {
				b.WriteByte(raw[i])
				i++
			}
			if i >= len(raw) {
				return "", errors.New("unterminated single-quoted value")
			}
			i++
		case '"':
			i++
			for i < len(raw) && raw[i] != '"' {
				if raw[i] == '\\' && i+1 < len(raw) {
					i++
				}
				b.WriteByte(raw[i])
				i++
			}
			if i >= len(raw) {
				return "", errors.New("unterminated double-quoted value")
			}
			i++
		case '\\':
			if i+1 < len(raw) {
				b.WriteByte(raw[i+1])
				i += 2
			} else {
				i++
			}
		case '#':
			if b.Len() == 0 || i == 0 || raw[i-1] == ' ' || raw[i-1] == '\t' {
				return strings.TrimSpace(b.String()), nil
			}
			b.WriteByte(raw[i])
			i++
		default:
			b.WriteByte(raw[i])
			i++
		}
	}
	return b.String(), nil
}

func isShellIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		if i == 0 && !(ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z') {
			return false
		}
		if !(ch == '_' || ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func loadConfig(path string) (*config, error) {
	file, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return &config{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var cfg config
	if err := json.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	return &cfg, nil
}

func saveConfig(path string, cfg *config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return writePrivateFile(path, data)
}

func writePrivateFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func sanitizeHostname(host string) string {
	var b strings.Builder
	for _, ch := range host {
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '.' {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// hostnameToVarSuffix converts a hostname (and optional port) into an uppercase
// shell variable suffix, e.g. "example.com" → "EXAMPLE_COM".
func hostnameToVarSuffix(host string) string {
	var b strings.Builder
	for _, ch := range strings.ToUpper(host) {
		if ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' {
			b.WriteRune(ch)
		} else {
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func renderGlobalLoader(tokensDir string) string {
	var b strings.Builder
	b.WriteString("# Generated by zero-trust-auth-cli\n")
	b.WriteString("# Source this file from your shell startup (.bashrc, .zshrc, etc.)\n")
	b.WriteString("# It loads all per-domain Cloudflare Access tokens and auto-renews expired ones.\n")
	b.WriteString("_cf_access_tokens_dir=")
	b.WriteString(shellQuote(tokensDir))
	b.WriteString("\n")
	b.WriteString(`for _cf_access_token_file in "$_cf_access_tokens_dir"/*.env; do
  [ -f "$_cf_access_token_file" ] && . "$_cf_access_token_file"
done
unset _cf_access_tokens_dir _cf_access_token_file
`)
	return b.String()
}

func defaultPaths() (appPaths, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return appPaths{}, err
	}
	configDir = filepath.Join(configDir, appName)
	return appPaths{
		ConfigDir:    configDir,
		ConfigFile:   filepath.Join(configDir, "config.json"),
		TokenFile:    filepath.Join(configDir, "token.env"),
		TokensDir:    filepath.Join(configDir, "tokens"),
		GlobalLoader: filepath.Join(configDir, "tokens.env"),
	}, nil
}

func expandPath(path string) (string, error) {
	path = os.ExpandEnv(path)
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

func normalizeResourceURL(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("empty resource URL")
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("resource URL must use http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("resource URL %q is missing a host", raw)
	}
	parsed.Fragment = ""
	return parsed, nil
}

func resourceOrigin(u *url.URL) string {
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

func wellKnownURL(raw, path string) (string, error) {
	u, err := normalizeResourceURL(raw)
	if err != nil {
		return "", err
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func shouldOpenBrowser() bool {
	if os.Getenv("SSH_CONNECTION") == "" && os.Getenv("SSH_CLIENT") == "" && os.Getenv("SSH_TTY") == "" {
		return true
	}
	return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
}

func openAuthURL(target string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", target)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", target)
	default:
		cmd = exec.Command("xdg-open", target)
	}
	return cmd.Start()
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func isAlphaNum(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func userAgent() string {
	return appName + "/" + version
}
