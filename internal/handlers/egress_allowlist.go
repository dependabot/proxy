package handlers

import (
	"net/http"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

// metricSender is the subset of the metrics client used by this handler. It is
// defined locally so the handler depends on the behaviour, not the concrete
// metrics package (and to avoid an import cycle).
type metricSender interface {
	SendMetric(name string, metricType string, value float64, additionalTags map[string]string) error
}

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
	metrics metricSender
}

// NewEgressAllowlistHandler builds the allowlist from the always-allowed GitHub
// infrastructure domains plus the static per-ecosystem defaults for the job's
// package manager. The observe/enforce toggles are driven by job experiments.
// The metrics client may be nil, in which case no telemetry is emitted.
func NewEgressAllowlistHandler(cfg *config.Config, env config.ProxyEnvSettings, metrics metricSender) *EgressAllowlistHandler {
	allowed := append([]string(nil), githubInfraDomains...)
	allowed = append(allowed, ecosystemDefaultDomains[env.PackageManager]...)

	return &EgressAllowlistHandler{
		observe: cfg.Experiments.Enabled(egressObserveExperiment),
		enforce: cfg.Experiments.Enabled(egressEnforceExperiment),
		allowed: allowed,
		metrics: metrics,
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

	// Record the real (unbucketed) host so we can see, per ecosystem (via the
	// package_manager default tag), which hosts jobs actually reach that are
	// not yet on the allowlist. Cardinality is naturally bounded to the long
	// tail of non-allowlisted hosts, which is exactly what we want to discover.
	h.recordNotAllowlisted(host)

	if h.observe {
		logging.RequestLogf(proxyCtx, "* egress not allowlisted %s", host)
	}
	if h.enforce {
		return req, goproxy.NewResponse(req, goproxy.ContentTypeText, http.StatusForbidden, "Forbidden")
	}
	return req, nil
}

// recordNotAllowlisted emits a counter tagged with the real request host. The
// package_manager tag is attached by the metrics client's default tags, so the
// resulting series answers "top hosts per ecosystem" for allowlist tuning.
func (h *EgressAllowlistHandler) recordNotAllowlisted(host string) {
	if h.metrics == nil {
		return
	}
	_ = h.metrics.SendMetric("egress_not_allowlisted_count", "increment", 1, map[string]string{"request_host": host})
}

func (h *EgressAllowlistHandler) isAllowed(host string) bool {
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
