package handlers

import (
	"net/url"
	"strings"

	"github.com/dependabot/proxy/internal/config"
)

// credentialHostKeys are the credential fields that carry a registry host or
// URL. The host of each is added to the per-job allowlist so that the private
// registries a job is configured to use are never treated as exfiltration.
var credentialHostKeys = []string{
	"host",
	"url",
	"index-url",
	"registry",
	"api-host",
	"repo",
	"endpoint",
	"replaces-base",
}

// hostFromValue extracts a lower-cased hostname from a credential value that may
// be a full URL ("https://host/path"), a bare host ("host"), or a host:port.
// It returns "" when no host can be determined.
func hostFromValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	// url.Parse only populates Hostname() when an authority is present, so add
	// the "//" marker for scheme-less values (bare host, host:port, host/path).
	if !strings.Contains(v, "://") {
		v = "//" + v
	}
	u, err := url.Parse(v)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// credentialHosts returns the hosts a job is explicitly configured to reach:
// the host of every URL-bearing credential field, plus any backend-supplied
// "domains" escape-hatch entries. These are inherently trusted for this job.
func credentialHosts(creds config.Credentials) []string {
	var hosts []string
	for _, c := range creds {
		for _, key := range credentialHostKeys {
			if h := hostFromValue(c.GetString(key)); h != "" {
				hosts = append(hosts, h)
			}
		}
		// Backend-supplied escape hatch: an explicit list of domains that the
		// proxy cannot otherwise derive (e.g. a registry that redirects
		// downloads to an unrelated CDN host). Entries may be bare hosts or
		// leading-dot suffix patterns; both are honoured by isAllowed.
		for _, d := range c.GetListOfStrings("domains") {
			if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
				hosts = append(hosts, d)
			}
		}
	}
	return hosts
}

// oidcExchangeHosts returns the identity-provider token-exchange endpoints the
// proxy itself contacts to mint a token when a credential is OIDC-configured.
// The eventual target registry host is already covered by credentialHosts (via
// url/api-host/registry), so only the provider auth endpoints are added here.
// Detection mirrors the identifying keys used by oidc.CreateOIDCCredential.
func oidcExchangeHosts(creds config.Credentials) []string {
	var hosts []string
	for _, c := range creds {
		// Azure AD.
		if c.GetString("tenant-id") != "" && c.GetString("client-id") != "" {
			hosts = append(hosts, "login.microsoftonline.com")
		}
		// AWS STS (CodeArtifact target host comes from the credential url).
		if c.GetString("aws-region") != "" && c.GetString("role-name") != "" {
			hosts = append(hosts, "sts.amazonaws.com")
		}
		// GCP Workload Identity Federation.
		if c.GetString("workload-identity-provider") != "" {
			hosts = append(hosts,
				"sts.googleapis.com",
				"iamcredentials.googleapis.com",
				"www.googleapis.com",
			)
		}
		// Cloudsmith.
		if c.GetString("service-slug") != "" && c.GetString("organization") != "" {
			apiHost := c.GetString("api-host")
			if apiHost == "" {
				apiHost = "api.cloudsmith.io"
			}
			hosts = append(hosts, strings.ToLower(apiHost))
		}
		// JFrog exchanges the token against the JFrog server itself, whose host
		// is already captured from the credential url by credentialHosts.
	}
	return hosts
}

// dynamicHosts returns the deduplicated per-job hosts derived from the job's
// credentials: configured registries, backend-supplied domains, and OIDC
// token-exchange endpoints.
func dynamicHosts(creds config.Credentials) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, h := range append(credentialHosts(creds), oidcExchangeHosts(creds)...) {
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
