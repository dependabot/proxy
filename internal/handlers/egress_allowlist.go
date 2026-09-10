package handlers

import (
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

// Experiment flags (job experiments) that toggle egress filtering. They are
// independent: observe logs non-allowlisted hosts, enforce drops them with a
// 403. Both default off (fail-open) when absent.
const (
	egressObserveExperiment = "proxy_egress_observe"
	egressEnforceExperiment = "proxy_egress_enforce"
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
// infrastructure domains, the union of every ecosystem's default registry hosts,
// and the job's dynamic hosts (configured registries and OIDC token-exchange
// endpoints derived from cfg.Credentials). The observe/enforce toggles are
// driven by job experiments.
func NewEgressAllowlistHandler(cfg *config.Config, env config.ProxyEnvSettings) *EgressAllowlistHandler {
	allowed := append([]string(nil), githubInfraDomains...)
	allowed = append(allowed, allEcosystemDomains...)
	allowed = append(allowed, dynamicHosts(cfg.Credentials)...)

	return &EgressAllowlistHandler{
		observe: cfg.Experiments.Enabled(egressObserveExperiment),
		enforce: cfg.Experiments.Enabled(egressEnforceExperiment),
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
	// Normalize an absolute DNS name (trailing dot) so exact matches treat
	// "registry.npmjs.org." as equivalent to "registry.npmjs.org", consistent
	// with HostMatchesDomain's boundary handling for the suffix form.
	host = strings.TrimSuffix(host, ".")
	for _, entry := range h.allowed {
		// A leading dot means "this domain and any subdomain"; otherwise the
		// entry must match the host exactly.
		if domain, ok := strings.CutPrefix(entry, "."); ok {
			if helpers.HostMatchesDomain(host, domain) {
				return true
			}
		} else if helpers.AreHostnamesEqual(host, entry) {
			return true
		}
	}
	return false
}
