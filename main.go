package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
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
	"runtime"
	"strconv"
	"strings"
	"time"
)

const appName = "zero-trust-auth-cli"

var version = "dev"

type config struct {
	Resource            string `json:"resource,omitempty"`
	TokenFile           string `json:"token_file,omitempty"`
	AuthorizationServer string `json:"authorization_server,omitempty"`
	UpdatedAt           string `json:"updated_at,omitempty"`
}

type appPaths struct {
	ConfigDir  string
	ConfigFile string
	TokenFile  string
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
  %[1]s config-path
  %[1]s version

Login flags:
  -resource URL          Protected Cloudflare Access URL. Overrides config.
  -out FILE              Sourceable shell output file. Defaults to the config dir.
  -config FILE           Config file path. Defaults to the config dir.
  -callback-host HOST    Loopback callback host: 127.0.0.1 or localhost. Defaults to 127.0.0.1.
  -timeout DURATION      Time to wait for browser authorization. Defaults to 5m.
  -no-browser            Print the authorization URL without trying to open a browser.

Example:
  %[1]s login https://example.com
  . "$(%[1]s config-path)/token.env"

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
	callbackHost := fs.String("callback-host", "127.0.0.1", "loopback callback host")
	timeout := fs.Duration("timeout", 5*time.Minute, "time to wait for browser authorization")
	noBrowser := fs.Bool("no-browser", false, "print auth URL without opening browser")
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
		outputPath = strings.TrimSpace(cfg.TokenFile)
	}
	if outputPath == "" {
		outputPath = paths.TokenFile
	}
	outputPath, err = expandPath(outputPath)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	httpClient := &http.Client{Timeout: 30 * time.Second}
	result, err := login(ctx, httpClient, resourceURL, *callbackHost, !*noBrowser, stdin, stderr)
	if err != nil {
		return err
	}

	shellFile := renderShellEnv(result, time.Now().UTC())
	if err := writePrivateFile(outputPath, []byte(shellFile)); err != nil {
		return err
	}

	cfg.Resource = result.Resource
	cfg.TokenFile = outputPath
	cfg.AuthorizationServer = result.AuthorizationServer
	cfg.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := saveConfig(configPath, cfg); err != nil {
		return err
	}

	fmt.Fprintf(stdout, "Wrote sourceable token file: %s\n", outputPath)
	fmt.Fprintf(stdout, "Load it with: . %s\n", shellQuote(outputPath))
	return nil
}

func login(ctx context.Context, client *http.Client, resourceURL *url.URL, callbackHost string, openBrowser bool, stdin io.Reader, logw io.Writer) (*loginResult, error) {
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
	token, err := exchangeCode(ctx, client, discovered.OAuth.TokenEndpoint, clientReg.ClientID, cb.RedirectURI, cbResult.Code, codeVerifier)
	if err != nil {
		return nil, err
	}
	if token.AccessToken == "" {
		return nil, errors.New("token endpoint response did not include access_token")
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
		"grant_types":                []string{"authorization_code"},
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

func exchangeCode(ctx context.Context, client *http.Client, endpoint, clientID, redirectURI, code, codeVerifier string) (tokenResponse, error) {
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

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return tokenResponse{}, fmt.Errorf("token exchange failed: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}

	var token tokenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&token); err != nil {
		return tokenResponse{}, err
	}
	return token, nil
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

func renderShellEnv(result *loginResult, generatedAt time.Time) string {
	expiresAt := ""
	if result.Token.ExpiresIn > 0 {
		expiresAt = result.IssuedAt.Add(time.Duration(result.Token.ExpiresIn) * time.Second).Format(time.RFC3339)
	}

	values := [][2]string{
		{"CF_ACCESS_TOKEN", result.Token.AccessToken},
		{"CF_ACCESS_REFRESH_TOKEN", result.Token.RefreshToken},
		{"CF_ACCESS_TOKEN_TYPE", result.Token.TokenType},
		{"CF_ACCESS_TOKEN_EXPIRES_IN", strconv.FormatInt(result.Token.ExpiresIn, 10)},
		{"CF_ACCESS_TOKEN_EXPIRES_AT", expiresAt},
		{"CF_ACCESS_RESOURCE", result.Token.Resource},
		{"CF_ACCESS_CLIENT_ID", result.ClientID},
		{"CF_ACCESS_AUTHORIZATION_SERVER", result.AuthorizationServer},
		{"CF_ACCESS_TOKEN_ENDPOINT", result.TokenEndpoint},
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
		b.WriteString("export ")
		b.WriteString(item[0])
		b.WriteByte('=')
		b.WriteString(shellQuote(item[1]))
		b.WriteByte('\n')
	}
	if result.Token.AccessToken != "" {
		b.WriteString("export CF_ACCESS_BEARER=")
		b.WriteString(shellQuote("Bearer " + result.Token.AccessToken))
		b.WriteByte('\n')
		b.WriteString("export CF_ACCESS_AUTHORIZATION_HEADER=")
		b.WriteString(shellQuote("Authorization: Bearer " + result.Token.AccessToken))
		b.WriteByte('\n')
	}
	return b.String()
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
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

func defaultPaths() (appPaths, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return appPaths{}, err
	}
	configDir = filepath.Join(configDir, appName)
	return appPaths{
		ConfigDir:  configDir,
		ConfigFile: filepath.Join(configDir, "config.json"),
		TokenFile:  filepath.Join(configDir, "token.env"),
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

func isAlphaNum(ch byte) bool {
	return ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
}

func userAgent() string {
	return appName + "/" + version
}
