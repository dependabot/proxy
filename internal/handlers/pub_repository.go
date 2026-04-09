package handlers

import (
	"net/http"

	"github.com/elazarl/goproxy"
	"github.com/sirupsen/logrus"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
	"github.com/dependabot/proxy/internal/oidc"
)

// PubRepositoryHandler handles requests to pub repositories, adding auth according to
// the v2 spec.
// https://github.com/dart-lang/pub/blob/db003f2ec3a0751337a1c8d4ff22d4863a28afe6/doc/repository-spec-v2.md
type PubRepositoryHandler struct {
	credentials  []pubRepositoryCredentials
	oidcRegistry *oidc.OIDCRegistry
}

type pubRepositoryCredentials struct {
	url   string
	token string
}

func NewPubRepositoryHandler(credentials config.Credentials) *PubRepositoryHandler {
	handler := PubRepositoryHandler{
		credentials:  []pubRepositoryCredentials{},
		oidcRegistry: oidc.NewOIDCRegistry(),
	}

	for _, credential := range credentials {
		if credential["type"] != "pub_repository" {
			continue
		}

		url := credential.GetString("url")

		// Pub credentials must remain URL-scoped; do not allow OIDC
		// registration to fall back to host-only matching when url is empty.
		// OIDC credentials are not used as static credentials.
		if url != "" {
			if oidcCred, _, _ := handler.oidcRegistry.Register(credential, []string{"url"}, "pub repository"); oidcCred != nil {
				continue
			}
		} else if oidcCred, _ := oidc.CreateOIDCCredential(credential); oidcCred != nil {
			continue
		}

		pubCred := pubRepositoryCredentials{
			url:   url,
			token: credential.GetString("token"),
		}
		if _, err := helpers.ParseURLLax(pubCred.url); err != nil {
			logrus.Warnf("ignoring invalid hosted url (%s): %v", pubCred.url, err)
			continue
		}
		if pubCred.token == "" {
			logrus.Warnf("missing token for hosted url (%s)", pubCred.url)
			continue
		}
		handler.credentials = append(handler.credentials, pubCred)
	}
	return &handler
}

func (h *PubRepositoryHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
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

		logging.RequestLogf(ctx, "* authenticating pub repository request (url: %s)", cred.url)
		req.Header.Set("Authorization", "Bearer "+cred.token)

		return req, nil
	}

	return req, nil
}
