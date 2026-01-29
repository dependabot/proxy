package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ecr"
	"github.com/aws/aws-sdk-go/service/ecr/ecriface"
	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
	"github.com/elazarl/goproxy"
	"github.com/stackrox/docker-registry-client/registry"
)

var (
	// Format: 123456789123.dkr.ecr.us-east-2.amazonaws.com
	ecrRe = regexp.MustCompile(`\A\d+.dkr.ecr.([a-z0-9-]+)\.amazonaws\.com\z`)
)

type getECRClient func(region, keyID, secretKey string) (ecriface.ECRAPI, error)

// DockerRegistryHandler handles requests to Docker registries, adding auth.
type DockerRegistryHandler struct {
	credentials     []*dockerRegistryCredentials
	transport       http.RoundTripper
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

// NewDockerRegistryHandler returns a new DockerRegistryHandler.
func NewDockerRegistryHandler(creds config.Credentials, transport http.RoundTripper, getECRClient getECRClient) *DockerRegistryHandler {
	handler := DockerRegistryHandler{
		credentials:     []*dockerRegistryCredentials{},
		transport:       transport,
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	if getECRClient == nil {
		getECRClient = defaultGetECRClient
	}

	for _, cred := range creds {
		if cred["type"] != "docker_registry" {
			continue
		}

		registry := cred.GetString("registry")
		if registry == "" {
			registry = cred.Host()
		}

		oidcCredential, _ := oidc.CreateOIDCCredential(cred)
		if oidcCredential != nil {
			if registry != "" {
				handler.oidcCredentials[registry] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for docker registry: %s", oidcCredential.Provider(), registry)
			}
			continue
		}

		registryCred := &dockerRegistryCredentials{
			registry:     registry,
			username:     cred.GetString("username"),
			password:     cred.GetString("password"),
			getECRClient: getECRClient,
		}
		handler.credentials = append(handler.credentials, registryCred)
	}

	return &handler
}

// Wraps a regular http.RoundTripper to make it goproxy.RoundTripper compatible
type dockerRegistryRoundTripper struct {
	transport http.RoundTripper
}

func (rt *dockerRegistryRoundTripper) RoundTrip(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
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
// set the request context's RoundTripper accordingly.
func (h *DockerRegistryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	if _, _, ok := req.BasicAuth(); ok {
		return req, nil
	}

	for _, cred := range h.credentials {
		if !helpers.UrlMatchesRequest(req, cred.registry, true) {
			continue
		}

		if cred.getECRCredentials(ctx) {
			logging.RequestLogf(ctx, "* authenticating docker ecr request (host: %s)", req.URL.Hostname())
			req.SetBasicAuth(cred.ecrUsername, cred.ecrPassword)
		} else {
			logging.RequestLogf(ctx, "* authenticating docker registry request (host: %s)", req.URL.Hostname())
			transport := &registry.BasicTransport{
				Transport: &registry.TokenTransport{
					Transport: h.transport,
					Username:  cred.getUsername(),
					Password:  cred.getPassword(),
				},
				URL:      fmt.Sprintf("https://%s", cred.registry),
				Username: cred.getUsername(),
				Password: cred.getPassword(),
			}
			ctx.RoundTripper = &dockerRegistryRoundTripper{
				transport: transport,
			}
		}

		return req, nil
	}

	return req, nil
}

func defaultGetECRClient(region, keyID, secretKey string) (ecriface.ECRAPI, error) {
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(region),
		Credentials: credentials.NewStaticCredentials(keyID, secretKey, ""),
	})
	if err != nil {
		return nil, err
	}

	return ecr.New(sess), nil
}

type dockerRegistryCredentials struct {
	registry     string
	username     string
	password     string
	ecrUsername  string
	ecrPassword  string
	getECRClient getECRClient
}

func (c *dockerRegistryCredentials) getECRCredentials(ctx *goproxy.ProxyCtx) bool {
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
	ecrSvc, err := c.getECRClient(region, c.username, c.password)
	if err != nil {
		logging.RequestLogf(ctx, "! failed to initialize aws client session (key_id=%s)", c.username)
		return false
	}

	rsp, err := ecrSvc.GetAuthorizationToken(&ecr.GetAuthorizationTokenInput{})
	if err != nil {
		logging.RequestLogf(ctx, "! failed to get ecr authorization token (key_id=%s)", c.username)
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
