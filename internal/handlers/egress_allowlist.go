package handlers

import (
	"net/http"
	"path"
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
	// allowed are the trusted, embedded defaults. Entries may use the leading-
	// dot suffix or glob forms and are matched with hostMatchesAllowlistEntry.
	allowed []string
	// dynamicHosts are the per-job hosts derived from the job's credentials.
	// They are matched EXACTLY only: credential values are not trusted to be
	// glob-free, so treating them as patterns (e.g. a configured "https://*.com")
	// would silently disable enforcement for every matching destination.
	dynamicHosts []string
	metrics      MetricSender
}

// NewEgressAllowlistHandler builds the allowlist from the always-allowed GitHub
// infrastructure domains, the shared third-party registry hosts, the union of
// every ecosystem's default registry hosts, and the job's dynamic hosts
// (configured registries and OIDC token-exchange endpoints derived from
// cfg.Credentials). The observe/enforce toggles are driven by job experiments.
// The metric sender, when non-nil, receives an observation for every host (with
// its allowlisted status) for reporting to the backend.
func NewEgressAllowlistHandler(cfg *config.Config, env config.ProxyEnvSettings, metricSender MetricSender) *EgressAllowlistHandler {
	allowed := append([]string(nil), githubInfraDomains...)
	allowed = append(allowed, sharedRegistryDomains...)
	allowed = append(allowed, allEcosystemDomains...)

	return &EgressAllowlistHandler{
		observe:      cfg.Experiments.Enabled(egressObserveExperiment),
		enforce:      cfg.Experiments.Enabled(egressEnforceExperiment),
		allowed:      allowed,
		dynamicHosts: dynamicHosts(cfg.Credentials),
		metrics:      metricSender,
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

	// A request is actually dropped only when it is not allowlisted AND enforce
	// mode is on; in observe-only mode a non-allowlisted host is logged but still
	// permitted. Capture this so Splunk can tell "observed, allowed through" from
	// "blocked with a 403" (the metric is the only signal forwarded there).
	blocked := !allowed && h.enforce

	// Record the observation here, at the point of the allowlist decision, so
	// that enforce-blocked hosts are captured before the 403 short-circuits the
	// request chain (the downstream metrics handler would never see them).
	h.recordHost(host, allowed, blocked)

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

func (h *EgressAllowlistHandler) recordHost(host string, allowed, blocked bool) {
	if h.metrics == nil {
		return
	}
	// package_manager is added by the collector's default tags. request_host is
	// the raw host; the backend buckets it before emitting to Datadog. blocked
	// distinguishes an enforce-mode 403 from an observe-only, still-permitted
	// host (both carry allowlisted=false).
	_ = h.metrics.SendMetric(egressHostMetric, "increment", 1, map[string]string{
		"request_host": host,
		"allowlisted":  strconv.FormatBool(allowed),
		"blocked":      strconv.FormatBool(blocked),
	})
}

func (h *EgressAllowlistHandler) isAllowed(host string) bool {
	// Normalize an absolute DNS name (trailing dot) so exact matches treat
	// "registry.npmjs.org." as equivalent to "registry.npmjs.org", consistent
	// with HostMatchesDomain's boundary handling for the suffix form.
	host = strings.TrimSuffix(host, ".")
	for _, entry := range h.allowed {
		if hostMatchesAllowlistEntry(host, entry) {
			return true
		}
	}
	// Per-job credential hosts are matched exactly only (never as globs or
	// subdomain suffixes), so an untrusted credential value cannot widen the
	// allowlist beyond the exact host the job was configured to reach.
	for _, entry := range h.dynamicHosts {
		if helpers.AreHostnamesEqual(host, entry) {
			return true
		}
	}
	return false
}

// hostMatchesAllowlistEntry reports whether host satisfies a single allowlist
// entry. An entry may be one of three forms:
//   - leading-dot suffix (".github.com"): matches that domain and any subdomain;
//   - glob pattern (contains "*", "?" or "[...]"): matched against the whole
//     host with path.Match. Path separators are irrelevant for hostnames, so
//     "*" spans dots and matches any subdomain depth;
//   - exact host: compared with AreHostnamesEqual.
//
// Note: glob entries are only as safe as the namespace they target. A pattern
// over a shared, multi-tenant storage domain (e.g. "*.blob.core.windows.net")
// can be satisfied by an attacker-registered name; prefer narrow patterns whose
// fixed components users cannot register. See egress_allowlist_defaults.yaml.
func hostMatchesAllowlistEntry(host, entry string) bool {
	if domain, ok := strings.CutPrefix(entry, "."); ok {
		// A leading dot means "this domain and any subdomain".
		return helpers.HostMatchesDomain(host, domain)
	}
	if isGlobPattern(entry) {
		matched, err := path.Match(strings.ToLower(entry), strings.ToLower(host))
		return err == nil && matched
	}
	// Otherwise the entry must match the host exactly.
	return helpers.AreHostnamesEqual(host, entry)
}

// isGlobPattern reports whether an allowlist entry contains glob metacharacters
// and should be matched with path.Match rather than compared exactly.
func isGlobPattern(entry string) bool {
	return strings.ContainsAny(entry, "*?[")
}
