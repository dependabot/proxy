package handlers

import (
	"net/http"
	"sync"

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
type CargoRegistryHandler struct {
	credentials     []cargoRepositoryCredentials
	oidcCredentials map[string]*oidc.OIDCCredential
	mutex           sync.RWMutex
}

type cargoRepositoryCredentials struct {
	url           string
	authorization string
}

func NewCargoRegistryHandler(credentials config.Credentials) *CargoRegistryHandler {
	handler := CargoRegistryHandler{
		credentials:     []cargoRepositoryCredentials{},
		oidcCredentials: make(map[string]*oidc.OIDCCredential),
	}

	for _, credential := range credentials {
		if credential["type"] != "cargo_registry" {
			continue
		}

		url := credential.GetString("url")

		oidcCredential, _ := oidc.CreateOIDCCredential(credential)
		if oidcCredential != nil {
			if url != "" {
				handler.oidcCredentials[url] = oidcCredential
				logging.RequestLogf(nil, "registered %s OIDC credentials for cargo registry: %s", oidcCredential.Provider(), url)
			}
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
	if oidc.TryAuthOIDCRequestWithPrefix(&h.mutex, h.oidcCredentials, req, ctx) {
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
