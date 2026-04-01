package handlers

import (
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

// HexOrganizationHandler handles requests to repo.hex.pm, adding auth.
type HexOrganizationHandler struct {
	credentials []hexOrganizationCredentials
}

type hexOrganizationCredentials struct {
	organization string
	key          string
}

// NewHexOrganizationHandler returns a new HexOrganizationHandler.
func NewHexOrganizationHandler(creds config.Credentials) *HexOrganizationHandler {
	handler := HexOrganizationHandler{credentials: []hexOrganizationCredentials{}}

	for _, cred := range creds {
		if cred["type"] != "hex_organization" {
			continue
		}

		org := cred.GetString("organization")
		key := cred.GetString("key")
		if org == "" || key == "" {
			continue
		}

		hexCred := hexOrganizationCredentials{
			organization: org,
			key:          key,
		}
		handler.credentials = append(handler.credentials, hexCred)
	}

	return &handler
}

// HandleRequest adds auth to an npm registry request
func (h *HexOrganizationHandler) HandleRequest(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if req.URL.Scheme != "https" || !helpers.MethodPermitted(req, "GET", "HEAD") || !helpers.CheckHost(req, "repo.hex.pm") {
		return req, nil
	}

	pathParts := strings.SplitN(strings.TrimLeft(req.URL.Path, "/"), "/", 3)
	if len(pathParts) < 2 {
		return req, nil
	}

	if pathParts[0] != "repos" {
		return req, nil
	}

	reqOrg := pathParts[1]
	for _, cred := range h.credentials {
		if cred.organization == reqOrg {
			logging.RequestLogf(ctx, "* authenticating hex request (org: %s)", reqOrg)
			req.Header.Set("authorization", cred.key)
			return req, nil
		}
	}

	return req, nil
}
