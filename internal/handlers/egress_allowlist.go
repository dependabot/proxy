package handlers

import (
	"net/http"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

// EgressAllowlistHandler filters outbound requests against a per-job allowlist
// of non-hostile domains. In observe mode it only logs non-allowlisted hosts;
// in enforce mode it drops them with a 403. When neither flag is set it allows
// all traffic (fail-open).
type EgressAllowlistHandler struct {
	observe bool
	enforce bool
	allowed []string
}

// NewEgressAllowlistHandler builds the allowlist from the always-allowed GitHub
// infrastructure domains plus the static per-ecosystem defaults for the job's
// package manager.
func NewEgressAllowlistHandler(cfg *config.Config, env config.ProxyEnvSettings) *EgressAllowlistHandler {
	allowed := append([]string(nil), githubInfraDomains...)
	allowed = append(allowed, ecosystemDefaultDomains[env.PackageManager]...)

	return &EgressAllowlistHandler{
		observe: cfg.EgressAllowlist.Observe,
		enforce: cfg.EgressAllowlist.Enforce,
		allowed: allowed,
	}
}

// HandleRequest logs and/or blocks requests whose host is not on the allowlist.
func (h *EgressAllowlistHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !h.observe && !h.enforce {
		return req, nil
	}

	host := helpers.GetHost(req)
	if host == "" || h.isAllowed(host) {
		return req, nil
	}

	if h.observe {
		logging.RequestLogf(proxyCtx, "* egress not allowlisted %s", host)
	}
	if h.enforce {
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
	}
	return req, nil
}

func (h *EgressAllowlistHandler) isAllowed(host string) bool {
	for _, domain := range h.allowed {
		if helpers.HostMatchesDomain(host, domain) {
			return true
		}
	}
	return false
}
