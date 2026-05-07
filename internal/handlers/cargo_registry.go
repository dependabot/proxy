package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// CargoRegistryHandler handles requests to cargo registries using the sparse protocol.
// When using cargo registries with the git protocol, the GitServerHandler should be used
// instead.
//
// Authentication is implemented as described in:
// https://rust-lang.github.io/rfcs/3139-cargo-alternative-registry-auth.html#reference-level-explanation
//
// This seems to be considered stable now:
// https://github.com/rust-lang/cargo/issues/10474
//
// A difference from other token based handlers is that this implementation directly sets the "Authorization"
// header to the value of token. This means the value of token may need to be prepended with additional
// metadata as required by the registry provider. For example, jfrog expects the "Authorization" header to
// contain:
// ```
// Authorization: Bearer <token>
// ```
//
// In that case, the supplied token value should be `Bearer <token>`. This would match how cargo stores the
// credentials locally in this example:
// https://jfrog.com/help/r/artifactory-how-to-integrate-artifactory-with-cargo-using-sparse-indexing/client-configuration
//
// Response Rewriting:
// When a registry responds with a config.json file containing the "auth-required" property,
// this handler removes that property before returning the response to the client (cargo command
// in the Dependabot updater container). This is necessary because the proxy is responsible for
// injecting authentication credentials into the request via the Authorization header. When cargo
// sees "auth-required": true, it expects to need authentication but no credentials are available
// in its configuration, causing it to error with "authenticated registries require a
// credential-provider to be configured". By removing this property, cargo treats the response as
// coming from an unauthenticated registry.
type CargoRegistryHandler struct {
	credentials  []cargoRepositoryCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type cargoRepositoryCredentials struct {
	url           string
	authorization string
}

func NewCargoRegistryHandler(credentials config.Credentials) *CargoRegistryHandler {
	handler := CargoRegistryHandler{
		credentials:  []cargoRepositoryCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, credential := range credentials {
		if credential["type"] != "cargo_registry" {
			continue
		}

		url := credential.GetString("url")

		// Cargo credentials must remain URL-scoped; do not allow OIDC
		// registration to fall back to host-only matching when url is empty.
		// OIDC credentials are not used as static credentials.
		if url != "" {
			if oidcCred, _, _ := handler.oidcRegistry.Register(credential, []string{"url"}, "cargo registry"); oidcCred != nil {
				continue
			}
		} else if oidcCred, _ := oidc.CreateOIDCCredential(credential); oidcCred != nil {
			continue
		}

		cargoCred := cargoRepositoryCredentials{
			url:           url,
			authorization: credential.GetString("token"),
		}
		if _, err := helpers.ParseURLLax(cargoCred.url); err != nil {
			logrus.Warnf("ignoring invalid registry url (%s): %v", cargoCred.url, err)
			continue
		}
		if cargoCred.authorization == "" {
			logrus.Warnf("missing token for registry url (%s)", cargoCred.url)
			continue
		}
		handler.credentials = append(handler.credentials, cargoCred)
	}
	return &handler
}

func (h *CargoRegistryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") {
		return req, nil
	}

	// Try OIDC credentials first
	if h.oidcRegistry.TryAuth(req, ctx) {
		return req, nil
	}

	// Fall back to static credentials
	for _, cred := range h.credentials {
		if !helpers.UrlMatchesRequest(req, cred.url, true) {
			continue
		}

		logging.RequestLogf(ctx, "* authenticating cargo registry request (url: %s)", cred.url)
		req.Header.Set("Authorization", cred.authorization)

		return req, nil
	}

	return req, nil
}

// HandleResponse rewrites the response if it's a config.json file with auth-required property
func (h *CargoRegistryHandler) HandleResponse(rsp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
	if rsp == nil || ctx == nil || ctx.Req == nil {
		return rsp
	}

	// Check if the request path ends with config.json
	requestPath := ctx.Req.URL.Path
	if !strings.HasSuffix(requestPath, "config.json") {
		return rsp
	}

	// Read the response body
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		logging.RequestLogf(ctx, "* error reading cargo registry response body: %v", err)
		return rsp
	}

	// Try to parse as JSON
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		logging.RequestLogf(ctx, "* cargo registry config.json response is not valid JSON, leaving unchanged")
		rsp.Body = io.NopCloser(bytes.NewReader(body))
		return rsp
	}

	// Check if auth-required property exists
	if _, hasAuthRequired := payload["auth-required"]; !hasAuthRequired {
		rsp.Body = io.NopCloser(bytes.NewReader(body))
		return rsp
	}

	// Remove auth-required property
	delete(payload, "auth-required")
	logging.RequestLogf(ctx, "* removing auth-required property from cargo registry config.json")

	// Serialize the modified JSON
	modifiedBody, err := json.Marshal(payload)
	if err != nil {
		logging.RequestLogf(ctx, "* error serializing modified cargo registry response: %v", err)
		rsp.Body = io.NopCloser(bytes.NewReader(body))
		return rsp
	}

	// Create a new response with the modified body
	rsp.Body = io.NopCloser(bytes.NewReader(modifiedBody))
	rsp.ContentLength = int64(len(modifiedBody))
	rsp.Header.Set("Content-Length", string(rune(len(modifiedBody))))

	return rsp
}
