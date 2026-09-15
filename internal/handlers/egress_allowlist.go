package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/elazarl/goproxy"

	"github.com/dependabot/proxy/internal/config"
	"github.com/dependabot/proxy/internal/helpers"
	"github.com/dependabot/proxy/internal/logging"
)

// Experiment flags (job experiments) that toggle egress filtering. They are
// independent: observe logs non-allowlisted hosts, enforce drops them with a
// 403. Both default off (fail-open) when absent.
//
// The keys are dash-cased to match the job-details payload: the API serializes
// experiments through the JSON:API adapter, whose default key transform is dash.
const (
	egressObserveExperiment = "proxy-egress-observe"
	egressEnforceExperiment = "proxy-egress-enforce"
)

// egressHostMetric is the metric emitted for every observed outbound host. The
// backend logs its raw request_host tag for allowlist discovery and buckets the
// host before forwarding to Datadog to keep tag cardinality low.
const egressHostMetric = "egress_host"

// MetricSender emits a metric for each observed outbound host, reusing the
// proxy's existing metrics collector (buffering, flushing, retries, and
// job-lifecycle handling) instead of a dedicated reporting pipeline.
type MetricSender interface {
	SendMetric(name string, metricType string, value float64, additionalTags map[string]string) error
}

// EgressAllowlistHandler filters outbound requests against a per-job allowlist
// of non-hostile domains. In observe mode it only logs non-allowlisted hosts;
// in enforce mode it drops them with a 403. When neither flag is set it allows
// all traffic (fail-open).
type EgressAllowlistHandler struct {
	observe bool
	enforce bool
	allowed []string
	metrics MetricSender
}

// NewEgressAllowlistHandler builds the allowlist from the always-allowed GitHub
// infrastructure domains, the union of every ecosystem's default registry hosts,
// and the job's dynamic hosts (configured registries and OIDC token-exchange
// endpoints derived from cfg.Credentials). The observe/enforce toggles are
// driven by job experiments. The metric sender, when non-nil, receives an
// observation for every host (with its allowlisted status) for reporting to the
// backend.
func NewEgressAllowlistHandler(cfg *config.Config, env config.ProxyEnvSettings, metricSender MetricSender) *EgressAllowlistHandler {
	allowed := append([]string(nil), githubInfraDomains...)
	allowed = append(allowed, allEcosystemDomains...)
	allowed = append(allowed, dynamicHosts(cfg.Credentials)...)

	return &EgressAllowlistHandler{
		observe: cfg.Experiments.Enabled(egressObserveExperiment),
		enforce: cfg.Experiments.Enabled(egressEnforceExperiment),
		allowed: allowed,
		metrics: metricSender,
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

	// Record the observation here, at the point of the allowlist decision, so
	// that enforce-blocked hosts are captured before the 403 short-circuits the
	// request chain (the downstream metrics handler would never see them).
	h.recordHost(host, allowed)

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

func (h *EgressAllowlistHandler) recordHost(host string, allowed bool) {
	if h.metrics == nil {
		return
	}
	// package_manager is added by the collector's default tags. request_host is
	// the raw host; the backend buckets it before emitting to Datadog.
	_ = h.metrics.SendMetric(egressHostMetric, "increment", 1, map[string]string{
		"request_host": host,
		"allowlisted":  strconv.FormatBool(allowed),
	})
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
