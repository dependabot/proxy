package handlers

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/elazarl/goproxy"
	"github.com/stackrox/docker-registry-client/registry"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

var (
	// Format: 123456789123.dkr.ecr.us-east-2.amazonaws.com
	ecrRe = regexp.MustCompile(`\A\d+.dkr.ecr.([a-z0-9-]+)\.amazonaws\.com\z`)
)

type ecrClient interface {
	GetAuthorizationToken(ctx context.Context, input *ecr.GetAuthorizationTokenInput, optFns ...func(*ecr.Options)) (*ecr.GetAuthorizationTokenOutput, error)
}

type getECRClient func(ctx context.Context, region, keyID, secretKey string, client *http.Client) (ecrClient, error)

// DockerRegistryHandler handles requests to Docker registries, adding auth.
type DockerRegistryHandler struct {
	credentials  []*dockerRegistryCredentials
	transport    http.RoundTripper
	oidcRegistry *oidc.OIDCRegistry
}

// NewDockerRegistryHandler returns a new DockerRegistryHandler.
func NewDockerRegistryHandler(creds config.Credentials, client *http.Client, getECRClient getECRClient) *DockerRegistryHandler {
	oidcRegistry := oidc.NewOIDCRegistry(client)
	handler := DockerRegistryHandler{
		credentials:  []*dockerRegistryCredentials{},
		transport:    client.Transport,
		oidcRegistry: oidcRegistry,
	}

	if getECRClient == nil {
		getECRClient = defaultGetECRClient
	}

	for _, cred := range creds {
		if cred["type"] != "docker_registry" {
			continue
		}

		registryLocation, matchLocation, matchField, ok := dockerCredentialLocations(cred)
		if !ok {
			continue
		}
		proxyOnly := cred.GetBool("proxy-only")
		matchURL, path, ok := dockerRegistryCredentialLocation(matchLocation, proxyOnly)
		if !ok {
			continue
		}

		if !proxyOnly {
			// OIDC credentials are not used as static credentials.
			oidcMatchingCred, urlFields := dockerOIDCMatchingCredential(cred, matchField, matchURL)
			if oidcCred, _, _ := handler.oidcRegistry.Register(oidcMatchingCred, urlFields, "docker registry"); oidcCred != nil {
				continue
			}
		}
		if proxyOnly && cred.GetString("username") == "" && cred.GetString("password") == "" {
			continue
		}

		parsedRegistry, err := helpers.ParseURLLax(registryLocation)
		if err != nil || parsedRegistry.Host == "" {
			continue
		}

		registryCred := &dockerRegistryCredentials{
			matchURL:     matchURL,
			registry:     parsedRegistry.Host,
			path:         path,
			username:     cred.GetString("username"),
			password:     cred.GetString("password"),
			httpClient:   client,
			getECRClient: getECRClient,
			proxyOnly:    proxyOnly,
		}
		handler.credentials = append(handler.credentials, registryCred)
	}

	return &handler
}

// Wraps a regular http.RoundTripper to make it goproxy.RoundTripper compatible
type dockerRegistryRoundTripper struct {
	transport http.RoundTripper
}

func (rt *dockerRegistryRoundTripper) RoundTrip(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Response, error) {
	return rt.transport.RoundTrip(req)
}

// HandleRequest adds auth to Docker registry requests. It's slightly more
// complicated than most other handlers, as the auth flow for Docker registries
// is:
//
//  1. Make a request with basic authentication to the registry.  If the registry
//     supports basic auth, get 200 response we're done.
//  2. If we get a 401 response to the above with a WWW-Authenticate header
//     which points to a token server.
//  3. Make a request to the token server using HTTP basic authentication. This
//     returns a JSON payload including a bearer token.
//  4. Use the bearer token to make an authenticated request to the registry.
//
// Fortunately, the github.com/stackrox/docker-registry-client/registry library's
// TokenTransport implements the bulk of this flow for us, so we just need to
// set the proxy context's RoundTripper accordingly.
func (h *DockerRegistryHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	oidcCredential := h.oidcRegistry.CredentialForRequest(req)
	if h.oidcRegistry.TryAuthCredential(req, proxyCtx, oidcCredential) {
		return req, nil
	}
	if hasUsableAuthorization(req) {
		return req, nil
	}
	if h.authenticateStaticCredential(req, proxyCtx, false) {
		return req, nil
	}
	if oidcCredential != nil {
		return req, nil
	}
	h.authenticateStaticCredential(req, proxyCtx, true)

	return req, nil
}

func (h *DockerRegistryHandler) authenticateStaticCredential(
	req *http.Request,
	proxyCtx *goproxy.ProxyCtx,
	proxyOnly bool,
) bool {
	if proxyOnly && !proxyOnlyCredentialRequestAllowed(req) {
		return false
	}

	for _, cred := range h.credentials {
		if cred.proxyOnly != proxyOnly {
			continue
		}
		matchedPath, ok := dockerCredentialMatchesRequest(req, cred)
		if !ok {
			continue
		}

		if cred.getECRCredentials(req.Context(), proxyCtx) {
			logging.RequestLogf(proxyCtx, "* authenticating docker ecr request (host: %s)", req.URL.Hostname())
			helpers.SetBasicAuthorization(req, cred.ecrUsername, cred.ecrPassword)
		} else {
			logging.RequestLogf(proxyCtx, "* authenticating docker registry request (host: %s)", req.URL.Hostname())
			transport := &registry.BasicTransport{
				Transport: &registry.TokenTransport{
					Transport: h.transport,
					Username:  cred.getUsername(),
					Password:  cred.getPassword(),
				},
				URL:      (&url.URL{Scheme: req.URL.Scheme, Host: req.URL.Host}).String() + matchedPath,
				Username: cred.getUsername(),
				Password: cred.getPassword(),
			}
			proxyCtx.RoundTripper = &dockerRegistryRoundTripper{
				transport: transport,
			}
		}

		return true
	}

	return false
}

func dockerCredentialMatchesRequest(
	req *http.Request,
	cred *dockerRegistryCredentials,
) (string, bool) {
	if !helpers.CredentialURLMatchesRequest(req, cred.matchURL, true) {
		return "", false
	}
	return helpers.MatchingPathPrefix(req.URL.EscapedPath(), cred.path)
}

func dockerOIDCMatchingCredential(
	cred config.Credential,
	field string,
	matchURL string,
) (config.Credential, []string) {
	if field == "" {
		return cred, nil
	}
	copy := make(config.Credential, len(cred))
	for key, value := range cred {
		copy[key] = value
	}
	copy[field] = matchURL
	return copy, []string{field}
}

func dockerCredentialLocations(cred config.Credential) (registry, match, matchField string, ok bool) {
	registry = cred.GetString("registry")
	configuredURL := cred.GetString("url")

	if registry == "" && configuredURL == "" {
		registry = cred.Host()
		if _, _, _, ok := parseDockerCredentialLocation(registry); !ok {
			return "", "", "", false
		}
		return registry, registry, "", true
	}
	if registry == "" {
		if _, _, _, ok := parseDockerCredentialLocation(configuredURL); !ok {
			return "", "", "", false
		}
		return configuredURL, configuredURL, "url", true
	}

	registryURL, registryPath, registrySpecificity, ok := parseDockerCredentialLocation(registry)
	if !ok {
		return "", "", "", false
	}
	if configuredURL == "" {
		return registry, registry, "registry", true
	}

	url, urlPath, urlSpecificity, ok := parseDockerCredentialLocation(configuredURL)
	if !ok {
		return "", "", "", false
	}
	if !dockerOriginsEqual(registryURL, url) {
		return "", "", "", false
	}
	if registryPath == urlPath {
		return registry, registry, "registry", true
	}
	if urlSpecificity > registrySpecificity &&
		helpers.PathMatches(url.EscapedPath(), registryURL.EscapedPath()) {
		return registry, configuredURL, "url", true
	}
	if registrySpecificity > urlSpecificity &&
		helpers.PathMatches(registryURL.EscapedPath(), url.EscapedPath()) {
		return registry, registry, "registry", true
	}
	return "", "", "", false
}

func parseDockerCredentialLocation(location string) (*url.URL, string, int, bool) {
	parsed, err := helpers.ParseURLLax(location)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return nil, "", 0, false
	}
	path, ok := helpers.CanonicalPath(parsed.EscapedPath())
	if !ok {
		return nil, "", 0, false
	}
	return parsed, path, strings.Count(path, "/"), true
}

func dockerOriginsEqual(a, b *url.URL) bool {
	scheme := func(url *url.URL) string {
		if url.Scheme == "" {
			return "https"
		}
		return strings.ToLower(url.Scheme)
	}
	port := func(url *url.URL) string {
		if url.Port() != "" {
			return url.Port()
		}
		if scheme(url) == "http" {
			return "80"
		}
		return "443"
	}

	return scheme(a) == scheme(b) &&
		port(a) == port(b) &&
		helpers.AreHostnamesEqual(a.Hostname(), b.Hostname())
}

func dockerRegistryCredentialLocation(location string, proxyOnly bool) (matchURL, path string, ok bool) {
	parsed, err := helpers.ParseURLLax(location)
	if err != nil || parsed.Host == "" {
		return "", "", false
	}

	path = strings.TrimRight(parsed.EscapedPath(), "/")
	if path == "" {
		if !proxyOnly {
			return location, "", true
		}
		parsed.Path = "/v2"
		parsed.RawPath = ""
		return parsed.String(), "/v2", true
	}
	canonicalPath, ok := helpers.CanonicalPath(path)
	if !ok {
		return "", "", false
	}
	if canonicalPath != "/v2" && !strings.HasPrefix(canonicalPath, "/v2/") {
		parsed.Path = "/v2" + strings.TrimRight(parsed.Path, "/")
		if parsed.RawPath != "" {
			parsed.RawPath = "/v2" + path
		}
		path = "/v2" + path
	}

	return parsed.String(), path, true
}

func defaultGetECRClient(ctx context.Context, region, keyID, secretKey string, client *http.Client) (ecrClient, error) {
	cfg, err := awsconfig.LoadDefaultConfig(
		ctx,
		awsconfig.WithRegion(region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(keyID, secretKey, "")),
		awsconfig.WithHTTPClient(client),
	)
	if err != nil {
		return nil, err
	}

	return ecr.NewFromConfig(cfg), nil
}

type dockerRegistryCredentials struct {
	matchURL     string
	registry     string
	path         string
	username     string
	password     string
	ecrUsername  string
	ecrPassword  string
	httpClient   *http.Client
	getECRClient getECRClient
	proxyOnly    bool
}

func (c *dockerRegistryCredentials) getECRCredentials(requestCtx context.Context, proxyCtx *goproxy.ProxyCtx) bool {
	if c.ecrUsername != "" && c.ecrPassword != "" {
		return true
	}

	regURL, err := helpers.ParseURLLax(c.registry)
	if err != nil {
		return false
	}

	match := ecrRe.FindStringSubmatch(regURL.Hostname())
	if match == nil || len(match) != 2 {
		return false
	}

	region := match[1]
	ecrSvc, err := c.getECRClient(requestCtx, region, c.username, c.password, c.httpClient)
	if err != nil {
		logging.RequestLogf(proxyCtx, "! failed to initialize aws ecr client (key_id=%s)", c.username)
		return false
	}

	rsp, err := ecrSvc.GetAuthorizationToken(requestCtx, &ecr.GetAuthorizationTokenInput{})
	if err != nil {
		logging.RequestLogf(proxyCtx, "! failed to get ecr authorization token (key_id=%s)", c.username)
		return false
	}

	for _, ad := range rsp.AuthorizationData {
		if ad.AuthorizationToken != nil {
			decoded, err := base64.StdEncoding.DecodeString(*ad.AuthorizationToken)
			if err != nil {
				continue
			}

			username, password, found := strings.Cut(string(decoded), ":")
			if !found {
				continue
			}
			c.ecrUsername = username
			c.ecrPassword = password
			return true
		}
	}
	return false
}

func (c *dockerRegistryCredentials) getUsername() string {
	if c.ecrUsername != "" {
		return c.ecrUsername
	}
	return c.username
}

func (c *dockerRegistryCredentials) getPassword() string {
	if c.ecrPassword != "" {
		return c.ecrPassword
	}
	return c.password
}
