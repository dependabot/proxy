package handlers

import (
	"net/http"
	"strings"

	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"

	"github.com/dependabot/proxy/internal/config"
	"github.com/elazarl/goproxy"
)

// HexOrganizationHandler handles requests to repo.hex.pm, adding auth.
type HexOrganizationHandler struct {
	orgTokens map[string]string
}

// NewHexOrganizationHandler returns a new HexOrganizationHandler.
func NewHexOrganizationHandler(creds config.Credentials) *HexOrganizationHandler {
	handler := HexOrganizationHandler{orgTokens: map[string]string{}}

	for _, cred := range creds {
		if cred["type"] != "hex_organization" {
			continue
		}

		org := cred.GetString("organization")
		token := cred.GetString("token")
		if org == "" || token == "" {
			continue
		}

		handler.orgTokens[org] = token
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

	token, ok := h.orgTokens[pathParts[1]]
	if !ok {
		return req, nil
	}

	logging.RequestLogf(ctx, "* authenticating hex request (org: %s)", pathParts[1])
	req.Header.Set("authorization", token)

	return req, nil
}
