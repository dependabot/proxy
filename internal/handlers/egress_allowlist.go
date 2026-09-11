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

// EgressHostRecorder buffers observed outbound hosts so they can be reported to
// the backend for egress-allowlist tuning.
type EgressHostRecorder interface {
	RecordHost(host string, allowlisted bool)
}

// EgressAllowlistHandler filters outbound requests against a per-job allowlist
// of non-hostile domains. In observe mode it only logs non-allowlisted hosts;
// in enforce mode it drops them with a 403. When neither flag is set it allows
// all traffic (fail-open).
type EgressAllowlistHandler struct {
	observe  bool
	enforce  bool
	allowed  []string
	recorder EgressHostRecorder
}

// NewEgressAllowlistHandler builds the allowlist from the always-allowed GitHub
// infrastructure domains, the union of every ecosystem's default registry hosts,
// and the job's dynamic hosts (configured registries and OIDC token-exchange
// endpoints derived from cfg.Credentials). The observe/enforce toggles are
// driven by job experiments. The recorder, when non-nil, receives every observed
// host (with its allowlisted status) for reporting to the backend.
func NewEgressAllowlistHandler(cfg *config.Config, env config.ProxyEnvSettings, recorder EgressHostRecorder) *EgressAllowlistHandler {
	allowed := append([]string(nil), githubInfraDomains...)
	allowed = append(allowed, allEcosystemDomains...)
	allowed = append(allowed, dynamicHosts(cfg.Credentials)...)

	return &EgressAllowlistHandler{
		observe:  cfg.Experiments.Enabled(egressObserveExperiment),
		enforce:  cfg.Experiments.Enabled(egressEnforceExperiment),
		allowed:  allowed,
		recorder: recorder,
	}
}

// HandleRequest logs and/or blocks requests whose host is not on the allowlist.
func (h *EgressAllowlistHandler) HandleRequest(req *http.Request, proxyCtx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
	if !h.observe && !h.enforce {
		return req, nil
	}

	host := helpers.GetHost(req)
	if host == "" {
		return req, nil
	}

	allowed := h.isAllowed(host)

	if h.recorder != nil {
		h.recorder.RecordHost(host, allowed)
	}

	if !allowed {
		if h.observe {
			logging.RequestLogf(proxyCtx, "* egress not allowlisted %s", host)
		}
		if h.enforce {
			return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
		}
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
